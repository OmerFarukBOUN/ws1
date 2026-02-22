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
REFRESH_INTERVAL = 10

# ANSI colors
BOLD = "\033[1m"
RED = "\033[31m"
RESET = "\033[0m"

username = ""
my_ip = ""
known_users = {}          # name -> ip
online_users = {}         # name -> ip
last_seen = {}            # name -> timestamp
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
    print(f"Sending packet to {ip}: {data}")
    subprocess.Popen(
        ["nc", ip, str(PORT)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ).communicate(data.encode())


def broadcast_ask():
    packet = {
        "type": "ASK",
        "SENDER_IP": my_ip
    }

    # common LAN broadcast patterns
    for suffix in range(1, 255):
        ip = ".".join(my_ip.split(".")[:3]) + f".{suffix}"
        send_packet(ip, packet)


def listener():
    while True:
        proc = subprocess.Popen(
            ["nc", "-l", str(PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )
        data = proc.stdout.read()
        print(data)
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
            last_seen[name] = time.time()

            if name in known_users and known_users[name] != ip:
                known_users[name] = ip  # mismatch handled visually
            else:
                known_users.setdefault(name, ip)

        elif msg.get("type") == "MESSAGE":
            sender = msg["SENDER_NAME"]
            payload = msg["PAYLOAD"]
            chat_history[sender].append(f"{sender}: {payload}")
            last_seen[sender] = time.time()


def menu():
    while True:
        time.sleep(REFRESH_INTERVAL)
        with lock:
            os.system("clear")
            print(f"Logged in as: {username} ({my_ip})\n")
            print("Users:\n")

            for name, ip in known_users.items():
                online = name in online_users and time.time() - last_seen.get(name, 0) < REFRESH_INTERVAL * 2
                mismatch = known_users[name] != online_users.get(name, known_users[name])

                display = name
                if online:
                    display = f"{BOLD}{name}{RESET}"
                if mismatch:
                    display = f"{RED}{name}{RESET}"

                print(f" - {display}")

            print("\nType username to chat, or ENTER to refresh")


def chat_with(target):
    os.system("clear")
    print(f"Chat with {target}\n")

    for line in chat_history[target]:
        print(line)

    while True:
        msg = input("> ")
        if msg == "":
            return

        packet = {
            "type": "MESSAGE",
            "SENDER_IP": my_ip,
            "SENDER_NAME": username,
            "PAYLOAD": msg[:MAX_PAYLOAD]
        }

        send_packet(known_users[target], packet)
        chat_history[target].append(f"You: {msg}")


def main():
    global username, my_ip

    username = input("Enter username: ").strip()
    my_ip = get_my_ip()

    threading.Thread(target=listener, daemon=True).start()

    broadcast_ask()
    threading.Thread(target=menu, daemon=True).start()

    while True:
        target = input("> ").strip()
        if target in known_users:
            chat_with(target)
        broadcast_ask()


if __name__ == "__main__":
    main()
