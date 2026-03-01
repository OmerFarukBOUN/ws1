#!/usr/bin/env python3
import socket
import threading
import json
import time
import os
import sys
from collections import defaultdict
import subprocess

PORT = 12487
MAX_PAYLOAD = 2048

# ANSI colors
BOLD = "\033[1m"
RED = "\033[31m"
RESET = "\033[0m"

username = ""
my_ip = ""
known_users = {}          # name -> ip
online_users = defaultdict(set)  # name -> ip_set
all_users = defaultdict(set)           # name -> ip_set
chat_history = defaultdict(list) # (name, ip) -> [messages]

lock = threading.Lock()
stop_listener = False
stop_chat = True

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

# The payload check was redundant, I was handling it elsewhere. Thus, I removed it.
def send_packet(ip, packet):
    try:
        data = json.dumps(packet).encode()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, PORT))
            s.sendall(data)
    except:
        pass

# We did not use send_packet(), since we do not need to dump the same packet multiple times
def broadcast_ask():
    global online_users
    packet = {
        "type": "ASK",
        "SENDER_IP": my_ip
    }
    online_users = defaultdict(set)  # reset online users
    data = json.dumps(packet).encode()
    base = ".".join(my_ip.split(".")[:3])

    for i in range(1, 255):
        ip = f"{base}.{i}"
        if ip == my_ip:
            continue

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((ip, PORT))
                s.sendall(data)
        except:
            pass
    time.sleep(1)

# server.accept() returns addr too, we can use it to identify if the sender is lying
def listener():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("", PORT))
        server.listen(5)

        while not stop_listener:
            try:
                conn, addr = server.accept()
                with conn:
                    data = conn.recv(MAX_PAYLOAD)
                    if not data:
                        continue
                    msg = json.loads(data.decode())
                    handle_packet(msg, addr)
            except:
                pass


def handle_packet(msg, addr):
    with lock:
        if msg.get("type") == "ASK":
            reply = {
                "type": "REPLY",
                "RECEIVER_NAME": username,
                "RECEIVER_IP": my_ip
            }
            send_packet(msg["SENDER_IP"], reply)

        elif msg.get("type") == "REPLY":
            name = msg["RECEIVER_NAME"]
            ip = msg["RECEIVER_IP"]
            online_users.setdefault(name, set()).add(ip)  # only set if not present
            all_users.setdefault(name, set()).add(ip)     # only set if not present
            draw_menu()

        elif msg.get("type") == "MESSAGE":
            sender = msg["SENDER_NAME"]
            payload = msg["PAYLOAD"]
            chat_history[sender].append(f"{sender}: {payload}")

def draw_menu():
    if not stop_chat:
        return
    os.system("clear")
    print(f"Logged in as: {username} ({my_ip})\n")
    print("Users:\n")
    with lock:
        for name, ip_set in all_users.items():
            for ip in ip_set:
                display = name
                if ip != known_users[name]:
                    display = f"{RED}{name}{RESET}"
                if ip in online_users[name]:
                    display = f"{BOLD}{name}{RESET}"
                print(f" - {display} ({ip})")

    print("\nType username to chat, or ENTER to refresh")
    print("\n> ", end="", flush=True)

def input_thread(target):
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

        send_packet(known_users[target], packet)

        with lock:
            chat_history[target].append(f"You: {msg}")

def chat_with(target):
    global stop_chat
    stop_chat = False

    os.system("clear")
    print(f"Chat with {target}")
    print("(Enter empty line or Ctrl+C to return)\n")
    print("\n> ", end="", flush=True)

    last_len = 0

    try:
        while not stop_chat:
            with lock:
                if len(chat_history[target]) != last_len:
                    os.system("clear")
                    print(f"Chat with {target}\n")
                    for line in chat_history[target]:
                        print(line)
                    print("\n> ", end="", flush=True)
                    last_len = len(chat_history[target])

            time.sleep(0.05)

    except KeyboardInterrupt:
        stop_chat = True

    print("\nLeaving chat...")



def main():
    global username, my_ip
    my_ip = get_my_ip()
    threading.Thread(target=listener, daemon=True).start()
    broadcast_ask()
    username = input("Enter username: ").strip()

    broadcast_ask()
    while True:
        draw_menu()
        try:
            target = input()
            target = target.split(" - ")
            for i in range(len(target)):
                target[i] = target[i].strip()
        except KeyboardInterrupt:
            stop_listener = True
            break
        if target[0] in all_users.keys():
            target_ip = target[1] if len(target) > 1 else all_users[target[0]][0]
            t = threading.Thread(target=input_thread, args=(target_ip,), daemon=True)
            t.start()
            chat_with(target[0])
        elif target != "":
            print("Unknown user.")
            time.sleep(1)
        else:
            broadcast_ask()
    sys.exit(0)
    

if __name__ == "__main__":
    main()
