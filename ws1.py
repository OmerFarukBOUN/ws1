#!/usr/bin/env python3
"""
lnchat.py — Local Network Chat
Transport: netcat (nc) subprocess calls on port 12487
JSON messaging protocol, curses TUI
"""

import curses
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime

# ── Constants ─────────────────────────────────────────────────────────────────
PORT         = 12487
MAX_PAYLOAD  = 2048
REFRESH_SEC  = 10

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Find the local 192.168.*.* IP by inspecting network interfaces."""
    try:
        import fcntl
        import struct
        import array

        SIOCGIFCONF = 0x8912
        SIOCGIFADDR = 0x8915

        # Get all interface names via SIOCGIFCONF
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        buf = array.array('B', b'\x00' * 4096)
        ifreq = struct.pack('iP', buf.buffer_info()[1], buf.buffer_info()[0])
        res   = fcntl.ioctl(s.fileno(), SIOCGIFCONF, ifreq)
        buflen = struct.unpack('i', res[:4])[0]
        s.close()

        # Parse interface records (name + sockaddr, each 40 bytes on Linux)
        offset = 0
        while offset + 40 <= buflen:
            name    = buf[offset:offset+16].tobytes().rstrip(b'\x00').decode(errors='ignore')
            family  = struct.unpack_from('H', buf, offset + 16)[0]
            if family == socket.AF_INET:
                ip = socket.inet_ntoa(struct.pack('4B', *buf[offset+20:offset+24]))
                if ip.startswith("192.168."):
                    return ip
            offset += 40

    except Exception:
        pass

    # Fallback: try getaddrinfo on the hostname
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip.startswith("192.168."):
                return ip
    except Exception:
        pass

    raise RuntimeError(
        "No 192.168.*.* interface found. "
        "Are you connected to a local network?"
    )

def get_broadcast_ip(local_ip: str) -> str:
    """Derive broadcast from local IP assuming /24."""
    parts = local_ip.split(".")
    parts[-1] = "255"
    return ".".join(parts)

def nc_available() -> bool:
    return shutil.which("nc") is not None or shutil.which("netcat") is not None

def nc_cmd() -> str:
    if shutil.which("nc"):
        return "nc"
    if shutil.which("netcat"):
        return "netcat"
    raise RuntimeError("netcat (nc) not found. Install it first.")

def send_via_nc(ip: str, port: int, data: bytes, timeout: float = 2.0) -> bool:
    """Send raw bytes to ip:port via `nc`. Returns True on success."""
    cmd = [nc_cmd(), "-w", str(int(timeout)), ip, str(port)]
    try:
        proc = subprocess.run(
            cmd,
            input=data,
            timeout=timeout + 1,
            capture_output=True
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False

def send_json_nc(ip: str, obj: dict, timeout: float = 2.0) -> bool:
    payload = json.dumps(obj).encode() + b"\n"
    return send_via_nc(ip, PORT, payload, timeout)

# ── Listener ──────────────────────────────────────────────────────────────────

class NCListener:
    """
    Runs `nc -l <port>` in a loop, reads one JSON line per connection,
    dispatches to a callback.
    """
    def __init__(self, port: int, on_message):
        self.port = port
        self.on_message = on_message
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            cmd = [nc_cmd(), "-l", str(self.port)]
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL
                )
                try:
                    # Read until EOF or timeout (5 s)
                    raw = b""
                    proc.wait(timeout=5)
                    raw = proc.stdout.read()
                except subprocess.TimeoutExpired:
                    proc.kill()
                    raw = proc.stdout.read()

                if raw:
                    for line in raw.split(b"\n"):
                        line = line.strip()
                        if line:
                            try:
                                obj = json.loads(line.decode())
                                self.on_message(obj)
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                pass
            except Exception:
                time.sleep(0.2)

# ── State ─────────────────────────────────────────────────────────────────────

class State:
    def __init__(self, username: str, local_ip: str):
        self.username  = username
        self.local_ip  = local_ip
        self.broadcast = get_broadcast_ip(local_ip)
        # ip -> name  (all known, persists for session)
        self.contacts: dict[str, str] = {}
        # ip -> name  (currently online, refreshed)
        self.online: dict[str, str] = {}
        # ip -> [(sender_name, text, hh:mm:ss)]
        self.history: dict[str, list] = defaultdict(list)
        self.lock = threading.RLock()
        # Event fired when online list changes
        self.updated = threading.Event()

    # ── Online tracking ───────────────────────────────────────────────────────

    def mark_online(self, ip: str, name: str):
        with self.lock:
            self.online[ip] = name
            # Store contact; if name changes remember both for mismatch detection
            if ip not in self.contacts:
                self.contacts[ip] = name
        self.updated.set()

    def refresh_cycle_start(self):
        """Call before broadcasting ASK — clears online set."""
        with self.lock:
            self.online.clear()

    def refresh_cycle_end(self):
        """After waiting for replies, mark cycle done."""
        self.updated.set()

    # ── Messages ──────────────────────────────────────────────────────────────

    def add_message(self, ip: str, sender_name: str, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            self.history[ip].append((sender_name, text, ts))
        self.updated.set()

    def get_history(self, ip: str) -> list:
        with self.lock:
            return list(self.history.get(ip, []))

    # ── Peer list for menu ────────────────────────────────────────────────────

    def peer_list(self):
        """
        Returns list of dicts:
          {ip, name, status}  status in: 'online' | 'offline' | 'mismatch'
        """
        with self.lock:
            seen = set()
            result = []

            for ip, name in self.online.items():
                if ip == self.local_ip:
                    continue
                stored = self.contacts.get(ip)
                if stored and stored != name:
                    status = "mismatch"
                else:
                    status = "online"
                result.append({"ip": ip, "name": name, "status": status})
                seen.add(ip)

            # Offline contacts that have chat history
            for ip, name in self.contacts.items():
                if ip in seen or ip == self.local_ip:
                    continue
                if self.history.get(ip):
                    result.append({"ip": ip, "name": name, "status": "offline"})

            return result

# ── Network Logic ─────────────────────────────────────────────────────────────

class Network:
    def __init__(self, state: State):
        self.state    = state
        self.listener = NCListener(PORT, self._dispatch)

    def start(self):
        self.listener.start()
        t = threading.Thread(target=self._broadcast_loop, daemon=True)
        t.start()

    def _dispatch(self, obj: dict):
        t = obj.get("type")
        if t == "ASK":
            sender_ip = obj.get("SENDER_IP", "")
            if sender_ip and sender_ip != self.state.local_ip:
                reply = {
                    "type": "REPLY",
                    "RECEIVER_NAME": self.state.username,
                    "RECEIVER_IP": self.state.local_ip,
                }
                send_json_nc(sender_ip, reply)

        elif t == "REPLY":
            name = obj.get("RECEIVER_NAME", "?")
            ip   = obj.get("RECEIVER_IP", "")
            if ip and ip != self.state.local_ip:
                self.state.mark_online(ip, name)

        elif t == "MESSAGE":
            sender_ip   = obj.get("SENDER_IP", "")
            sender_name = obj.get("SENDER_NAME", "?")
            payload     = obj.get("PAYLOAD", "")
            if sender_ip and sender_ip != self.state.local_ip:
                # Clamp payload
                payload = payload[:MAX_PAYLOAD]
                self.state.add_message(sender_ip, sender_name, payload)
                # Also mark them online / update contacts
                self.state.mark_online(sender_ip, sender_name)

    def _broadcast_loop(self):
        while True:
            self.state.refresh_cycle_start()
            ask = {"type": "ASK", "SENDER_IP": self.state.local_ip}
            send_json_nc(self.state.broadcast, ask)
            # Wait for replies
            time.sleep(3)
            self.state.refresh_cycle_end()
            # Sleep rest of refresh window
            time.sleep(REFRESH_SEC - 3)

    def send_message(self, peer_ip: str, text: str):
        msg = {
            "type": "MESSAGE",
            "SENDER_IP":   self.state.local_ip,
            "SENDER_NAME": self.state.username,
            "PAYLOAD":     text[:MAX_PAYLOAD],
        }
        ok = send_json_nc(peer_ip, msg)
        if ok:
            self.state.add_message(peer_ip, self.state.username, text[:MAX_PAYLOAD])
        return ok

# ── TUI ───────────────────────────────────────────────────────────────────────

# Color pair IDs
CP_NORMAL  = 1
CP_BOLD    = 2   # online  (white bold)
CP_RED     = 3   # mismatch
CP_DIM     = 4   # offline
CP_HEADER  = 5
CP_INPUT   = 6
CP_SELF    = 7
CP_PEER    = 8
CP_TIME    = 9
CP_STATUS  = 10

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(CP_NORMAL, curses.COLOR_WHITE,   -1)
    curses.init_pair(CP_BOLD,   curses.COLOR_CYAN,    -1)
    curses.init_pair(CP_RED,    curses.COLOR_RED,     -1)
    curses.init_pair(CP_DIM,    curses.COLOR_WHITE,   -1)
    curses.init_pair(CP_HEADER, curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(CP_INPUT,  curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(CP_SELF,   curses.COLOR_GREEN,   -1)
    curses.init_pair(CP_PEER,   curses.COLOR_CYAN,    -1)
    curses.init_pair(CP_TIME,   curses.COLOR_YELLOW,  -1)
    curses.init_pair(CP_STATUS, curses.COLOR_BLACK,   curses.COLOR_YELLOW)

def draw_border_box(win, title: str = ""):
    win.box()
    if title:
        h, w = win.getmaxyx()
        t = f" {title} "
        win.addstr(0, max(2, (w - len(t)) // 2), t,
                   curses.color_pair(CP_HEADER) | curses.A_BOLD)

def safe_addstr(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h:
        return
    max_len = w - x - 1
    if max_len <= 0:
        return
    try:
        win.addstr(y, x, text[:max_len], attr)
    except curses.error:
        pass

# ── Main Menu ─────────────────────────────────────────────────────────────────

def menu_screen(stdscr, state: State, network: Network):
    curses.curs_set(0)
    stdscr.nodelay(True)
    selected = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        # Header
        header = f" lnchat  ·  {state.username}  ·  {state.local_ip} "
        header = header[:w]
        try:
            stdscr.addstr(0, 0, header.ljust(w), curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

        # Sub-header
        sub = " ↑↓ navigate   ENTER select   Q quit "
        safe_addstr(stdscr, 1, 0, sub.ljust(w), curses.color_pair(CP_STATUS))

        peers = state.peer_list()

        if not peers:
            safe_addstr(stdscr, 3, 2,
                        "Scanning network… (no peers found yet)",
                        curses.color_pair(CP_DIM) | curses.A_DIM)
        else:
            # Clamp selection
            selected = max(0, min(selected, len(peers) - 1))

            safe_addstr(stdscr, 3, 2, "CONTACTS", curses.color_pair(CP_NORMAL) | curses.A_UNDERLINE)

            for idx, peer in enumerate(peers):
                row = 4 + idx
                if row >= h - 2:
                    break

                is_sel   = (idx == selected)
                status   = peer["status"]
                name     = peer["name"]
                ip       = peer["ip"]
                has_hist = bool(state.history.get(ip))

                # Indicator
                if status == "online":
                    indicator = "● "
                    attr = curses.color_pair(CP_BOLD) | curses.A_BOLD
                elif status == "mismatch":
                    indicator = "⚠ "
                    attr = curses.color_pair(CP_RED) | curses.A_BOLD
                else:
                    indicator = "○ "
                    attr = curses.color_pair(CP_DIM) | curses.A_DIM

                line = f"{indicator}{name:<20} {ip}"

                if is_sel:
                    # Highlight entire row
                    bar = line.ljust(w - 2)
                    try:
                        stdscr.addstr(row, 1, bar,
                                      curses.color_pair(CP_INPUT) | curses.A_BOLD)
                    except curses.error:
                        pass
                else:
                    safe_addstr(stdscr, row, 3, line, attr)

                # Unread marker / history dot
                if has_hist and status != "online":
                    safe_addstr(stdscr, row, w - 4, "msg",
                                curses.color_pair(CP_TIME))

        # Footer countdown
        safe_addstr(stdscr, h - 1, 0,
                    f" Refreshing every {REFRESH_SEC}s — last scan: {datetime.now().strftime('%H:%M:%S')}",
                    curses.color_pair(CP_DIM) | curses.A_DIM)

        stdscr.refresh()

        # Input
        key = stdscr.getch()
        if key == curses.KEY_UP:
            selected = max(0, selected - 1)
        elif key == curses.KEY_DOWN:
            selected = min(max(0, len(peers) - 1), selected + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            if peers:
                peer = peers[selected]
                chat_screen(stdscr, state, network, peer["ip"], peer["name"])
                # Restore menu state
                curses.curs_set(0)
                stdscr.nodelay(True)
        elif key in (ord('q'), ord('Q')):
            break

        # Auto-refresh every 0.5s
        state.updated.wait(timeout=0.5)
        state.updated.clear()

# ── Chat Screen ───────────────────────────────────────────────────────────────

def chat_screen(stdscr, state: State, network: Network, peer_ip: str, peer_name: str):
    curses.curs_set(1)
    stdscr.nodelay(False)
    stdscr.timeout(300)

    input_buf = []
    scroll_offset = 0  # lines from bottom (0 = latest)

    def redraw():
        nonlocal scroll_offset
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        # Header
        hdr = f" chat: {peer_name}  ({peer_ip})  ·  ESC=back "
        try:
            stdscr.addstr(0, 0, hdr[:w].ljust(w),
                          curses.color_pair(CP_HEADER) | curses.A_BOLD)
        except curses.error:
            pass

        # Message area: rows 1..(h-3)
        msg_h = h - 3
        messages = state.get_history(peer_ip)

        # Build wrapped lines
        wrapped = []
        for sender, text, ts in messages:
            is_self = (sender == state.username)
            prefix = f"[{ts}] {sender}: "
            full   = prefix + text
            # Simple wrap
            while full:
                wrapped.append((full[:w - 2], is_self, ts if full == prefix + text else ""))
                full = full[w - 2:]

        total = len(wrapped)
        # Clamp scroll
        max_scroll = max(0, total - msg_h)
        scroll_offset = min(scroll_offset, max_scroll)
        start_idx = max(0, total - msg_h - scroll_offset)
        visible   = wrapped[start_idx: start_idx + msg_h]

        for row_i, (line, is_self, _) in enumerate(visible):
            row = 1 + row_i
            attr = curses.color_pair(CP_SELF) if is_self else curses.color_pair(CP_PEER)
            safe_addstr(stdscr, row, 1, line, attr)

        # Divider
        div_row = h - 2
        try:
            stdscr.addstr(div_row, 0, "─" * w, curses.color_pair(CP_DIM))
        except curses.error:
            pass

        # Input line
        prompt = f" ❯ "
        inp_str = "".join(input_buf)
        # Truncate display if too wide
        visible_inp = inp_str[-(w - len(prompt) - 2):]
        try:
            stdscr.addstr(h - 1, 0, (prompt + visible_inp).ljust(w),
                          curses.color_pair(CP_INPUT))
            stdscr.move(h - 1, len(prompt) + len(visible_inp))
        except curses.error:
            pass

        stdscr.refresh()

    redraw()

    while True:
        key = stdscr.getch()

        if key == 27:              # ESC — back to menu
            break

        elif key == curses.KEY_BACKSPACE or key == 127:
            if input_buf:
                input_buf.pop()

        elif key in (curses.KEY_ENTER, 10, 13):
            text = "".join(input_buf).strip()
            if text:
                input_buf.clear()
                ok = network.send_message(peer_ip, text)
                if not ok:
                    state.add_message(peer_ip, "system",
                                      f"[failed to deliver — {peer_ip} may be offline]")

        elif key == curses.KEY_UP:
            scroll_offset += 1

        elif key == curses.KEY_DOWN:
            scroll_offset = max(0, scroll_offset - 1)

        elif 32 <= key <= 126:    # printable
            if len("".join(input_buf)) < MAX_PAYLOAD:
                input_buf.append(chr(key))

        elif key == -1:            # timeout — just redraw (for incoming msgs)
            pass

        redraw()

# ── Bootstrap ─────────────────────────────────────────────────────────────────

def ask_username() -> str:
    print("\n╔══════════════════════════════╗")
    print("║        lnchat  v1.0          ║")
    print("║  Local Network Chat (raw)    ║")
    print("╚══════════════════════════════╝\n")
    while True:
        name = input("  Enter your username: ").strip()
        if 1 <= len(name) <= 32 and name.isprintable():
            return name
        print("  [!] Username must be 1-32 printable characters.")

def main():
    if not nc_available():
        print("[ERROR] netcat (nc) is not installed or not in PATH.")
        print("        Install it with: sudo apt install netcat-openbsd")
        sys.exit(1)

    username = ask_username()
    local_ip = get_local_ip()

    print(f"\n  Local IP : {local_ip}")
    print(f"  Port     : {PORT}")
    print(f"  Broadcast: {get_broadcast_ip(local_ip)}")
    print("\n  Starting listener and scanning network…")
    time.sleep(0.5)

    state   = State(username, local_ip)
    network = Network(state)
    network.start()

    # Give listener a moment to bind, then do first broadcast
    time.sleep(1)

    def run_tui(stdscr):
        init_colors()
        menu_screen(stdscr, state, network)

    try:
        curses.wrapper(run_tui)
    except KeyboardInterrupt:
        pass

    print("\n  Bye!\n")

if __name__ == "__main__":
    main()