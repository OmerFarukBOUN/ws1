#!/usr/bin/env python3
import subprocess
import threading
import json
import time
import os
import sys
from collections import defaultdict

PORT = 12487
MAX_PAYLOAD = 2048

# ANSI colors
BOLD = "\033[1m"
RED = "\033[31m"
RESET = "\033[0m"

username = ""
my_ip = ""
known_users = {}          # name -> ip
online_users = {}         # name -> ip
chat_history = defaultdict(list)

lock = threading.Lock()


def get_my_ip():
    out = subprocess.check_output(["hostname", "-I"]).decode().strip()
    for ip in out.split():
        if ip.startswith("192.168."):
            return ip
    print("No 192.168.*.* IP found")
    sys.exit(1)


def send_packet(ip, packet):
    data = json.dumps(packet)
    if len(data.encode()) > MAX_PAYLOAD:
        return
    subprocess.Popen(
        ["nc", "-q", "0", ip, str(PORT)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ).communicate(data.encode())


def broadcast_ask():
    packet = {
        "type": "ASK",
        "SENDER_IP": my_ip
    }

    data = json.dumps(packet).encode()
    base = ".".join(my_ip.split(".")[:3])

    for i in range(1, 255):
        ip = f"{base}.{i}"
        if ip == my_ip:
            continue

        try:
            p = subprocess.Popen(
                ["nc", "-w", "1", ip, str(PORT)],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            p.stdin.write(data)
            p.stdin.close()
            # DO NOT wait(), DO NOT communicate()
        except:
            pass

def listener():
    while True:
        proc = subprocess.Popen(
            ["nc", "-l", str(PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )
        data = proc.stdout.read()
        try:
            msg = json.loads(data.decode())
            handle_packet(msg)
        except:
            pass


def handle_packet(msg):
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

            online_users[name] = ip

            if name in known_users and known_users[name] != ip:
                known_users[name] = ip  # mismatch handled visually
            else:
                known_users.setdefault(name, ip)

        elif msg.get("type") == "MESSAGE":
            sender = msg["SENDER_NAME"]
            payload = msg["PAYLOAD"]
            chat_history[sender].append(f"{sender}: {payload}")

def draw_menu():
    os.system("clear")
    print(f"Logged in as: {username} ({my_ip})\n")
    print("Users:\n")
    with lock:
        for name, ip in known_users.items():
            online = name in online_users
            mismatch = known_users[name] != online_users.get(name, known_users[name])

            display = name
            if online:
                display = f"{BOLD}{name}{RESET}"
            if mismatch:
                display = f"{RED}{name}{RESET}"

            print(f" - {display}")

    print("\nType username to chat, or ENTER to refresh")
    print("\n> ", end="", flush=True)

stop_chat = False

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
        target = input().strip()
        if target in known_users:
            t = threading.Thread(target=input_thread, args=(target,), daemon=True)
            t.start()
            chat_with(target)
        elif target != "":
            print("Unknown user.")
            time.sleep(1)
        else:
            broadcast_ask()

if __name__ == "__main__":
    main()
