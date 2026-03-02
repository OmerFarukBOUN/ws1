#!/usr/bin/env python3
import threading
import json
import time
import os
import sys
from collections import defaultdict
import socket
import subprocess


PORT = 12487
MAX_PAYLOAD = 2048

# ANSI colors
BOLD = "\033[1m"
RED = "\033[31m"
GRAY = "\033[90m"
RESET = "\033[0m"

username = ""
my_ip = ""
online_users = set()   # set of ips
all_users = {}      # ip -> name
chat_history = defaultdict(list)  # (name, ip) -> [messages]

lock = threading.Lock()
stop_listener = False


def get_my_ip():
    # Try connecting to 8.8.8.8
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass

    # Try connecting to 10.255.255.255
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass

    # Fallback: parse hostname -I for 192.168.*.* address
    out = subprocess.check_output(["hostname", "-I"]).decode().strip()
    for ip in out.split():
        if ip.startswith("192.168."):
            return ip

    print("No 192.168.*.* IP found")
    sys.exit(1)


def send_packet(ip, packet):
    data = json.dumps(packet).encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, PORT))
        s.sendall(data)
        s.close()
    except Exception:
        pass



# We did not use send_packet(), since we do not need to dump the same packet multiple times
def broadcast_ask():
    online_users.clear()
    packet = {
        "type": "ASK",
        "SENDER_IP": my_ip
    }
    data = json.dumps(packet).encode()
    base = ".".join(my_ip.split(".")[:3])

    def probe(ip):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((ip, PORT))
                s.sendall(data)
        except:
            pass

    threads = []
    for i in range(1, 255):
        ip = f"{base}.{i}"
        if ip == my_ip:
            continue
        t = threading.Thread(target=probe, args=(ip,), daemon=True)
        t.start()
        threads.append(t)

def listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("", PORT))
    srv.listen(16)
    srv.settimeout(1)
    while not stop_listener:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        peer_ip = addr[0]
        try:
            data = b""
            conn.settimeout(2)
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            conn.close()
            msg = json.loads(data.decode())
            handle_packet(msg, peer_ip)
        except Exception:
            pass
    srv.close()


def handle_packet(msg, peer_ip):
    with lock:
        if msg.get("type") == "ASK":
            # Validate sender IP
            if msg.get("SENDER_IP") != peer_ip:
                return
            reply = {
                "type": "REPLY",
                "RECEIVER_NAME": username,
                "RECEIVER_IP": my_ip
            }
            threading.Thread(target=send_packet, args=(peer_ip, reply), daemon=True).start()

        elif msg.get("type") == "REPLY":
            name = msg.get("RECEIVER_NAME", "")
            ip = msg.get("RECEIVER_IP", "")
            if not name or not ip:
                return

            # If ip already known under a different name, overwrite
            all_users[ip] = name
            online_users.add(ip)

        elif msg.get("type") == "MESSAGE":
            # Validate sender IP
            if msg.get("SENDER_IP") != peer_ip:
                return
            sender_name = msg.get("SENDER_NAME", "")
            payload = msg.get("PAYLOAD", "")
            key = (sender_name, peer_ip)
            chat_history[key].append(f"{sender_name}: {payload}")


def draw_menu():
    os.system("clear")
    print(f"Logged in as: {username} ({my_ip})\n")
    print("Users:\n")
    with lock:
        for ip, name in all_users.items():
            ip_str = f" {GRAY}({ip}){RESET}"
            if ip in online_users:
                print(f" - {BOLD}{name}{RESET}{ip_str}")
            else:
                print(f" - {name}{ip_str}")

    print("\nType username to chat, or ENTER to refresh")
    print("\n> ", end="", flush=True)

stop_chat = False

def input_thread(target_name, target_ip):
    global stop_chat
    while not stop_chat:
        try:
            msg = input("> ")
        except KeyboardInterrupt:
            stop_chat = True
            break

        if msg == "":
            stop_chat = True
            break

        packet = {
            "type": "MESSAGE",
            "SENDER_IP": my_ip,
            "SENDER_NAME": username,
            "PAYLOAD": msg[:MAX_PAYLOAD]
        }

        send_packet(target_ip, packet)

        with lock:
            chat_history[(target_name, target_ip)].append(f"You: {msg}")


def chat_with(target_name, target_ip):
    global stop_chat
    stop_chat = False

    os.system("clear")
    print(f"Chat with {target_name} ({target_ip})")
    print("(Enter empty line or Ctrl+C to return)\n")
    print("\n> ", end="", flush=True)

    last_len = 0
    key = (target_name, target_ip)

    try:
        while not stop_chat:
            with lock:
                if len(chat_history[key]) != last_len:
                    os.system("clear")
                    print(f"Chat with {target_name} ({target_ip})\n")
                    for line in chat_history[key]:
                        print(line)
                    print("\n> ", end="", flush=True)
                    last_len = len(chat_history[key])

            time.sleep(0.05)

    except KeyboardInterrupt:
        stop_chat = True

    print("\nLeaving chat...")


def resolve_target(target_name):
    with lock:
        matches = [(name, ip) for ip, name in all_users.items() if name == target_name]

    if not matches:
        matches = [(name, ip) for ip, name in all_users.items() if f"{name} - {ip}" == target_name]

    if matches:
        return matches[0]
    return None


def main():
    global username, my_ip, stop_listener
    my_ip = get_my_ip()
    threading.Thread(target=listener, daemon=True).start()
    broadcast_ask()
    username = input("Enter username: ").strip()
    broadcast_ask()
    while True:
        draw_menu()
        try:
            target = input()
            target = target.strip()
        except KeyboardInterrupt:
            stop_listener = True
            break

        if target == "":
            broadcast_ask()
            time.sleep(1)
            continue

        resolved = resolve_target(target)
        if resolved:
            t_name, t_ip = resolved
            t = threading.Thread(target=input_thread, args=(t_name, t_ip), daemon=True)
            t.start()
            chat_with(t_name, t_ip)
        else:
            print("Unknown user.")
            time.sleep(1)
    sys.exit(0)

if __name__ == "__main__":
    main()