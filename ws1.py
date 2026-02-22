#!/usr/bin/env python3
import subprocess
import threading
import json
import time
import os
import socket
import sys

PORT = 12487
MAX_PAYLOAD = 2048
REFRESH_INTERVAL = 10

contacts = {}       # name -> ip
online = {}         # name -> ip
chats = {}          # name -> [messages]
lock = threading.Lock()

# ---------- terminal helpers ----------
BOLD = "\033[1m"
RED = "\033[31m"
RESET = "\033[0m"

def clear():
    os.system("clear")

# ---------- networking ----------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("192.168.1.1", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

MY_IP = get_local_ip()
SUBNET = ".".join(MY_IP.split(".")[:3])

# ---------- netcat wrappers ----------
def nc_send(ip, data):
    try:
        p = subprocess.Popen(
            ["nc", ip, str(PORT)],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        p.communicate(json.dumps(data).encode(), timeout=1)
    except:
        pass

def nc_listen():
    p = subprocess.Popen(
        ["nc", "-l", "-p", str(PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    )
    out, _ = p.communicate()
    if not out:
        return None
    try:
        return json.loads(out.decode())
    except:
        return None

# ---------- protocol ----------
def broadcast_ask():
    packet = {
        "type": "ASK",
        "SENDER_IP": MY_IP
    }
    for i in range(1, 255):
        ip = f"{SUBNET}.{i}"
        if ip != MY_IP:
            nc_send(ip, packet)

def handle_packet(pkt):
    global online
    if pkt["type"] == "ASK":
        reply = {
            "type": "REPLY",
            "RECEIVER_NAME": USERNAME,
            "RECEIVER_IP": MY_IP
        }
        nc_send(pkt["SENDER_IP"], reply)

    elif pkt["type"] == "REPLY":
        with lock:
            online[pkt["RECEIVER_NAME"]] = pkt["RECEIVER_IP"]
            contacts.setdefault(pkt["RECEIVER_NAME"], pkt["RECEIVER_IP"])

    elif pkt["type"] == "MESSAGE":
        name = pkt["SENDER_NAME"]
        chats.setdefault(name, []).append(
            f"{name}: {pkt['PAYLOAD']}"
        )

# ---------- background threads ----------
def listener():
    while True:
        pkt = nc_listen()
        if pkt:
            handle_packet(pkt)

def refresher():
    while True:
        with lock:
            online.clear()
        broadcast_ask()
        time.sleep(REFRESH_INTERVAL)

# ---------- UI ----------
def show_menu():
    clear()
    print(f"Your name: {USERNAME} | IP: {MY_IP}\n")
    for name, ip in contacts.items():
        if name in online:
            print(f"{BOLD}{name}{RESET}")
        elif ip != contacts[name]:
            print(f"{RED}{name}{RESET}")
        else:
            print(name)
    print("\nSelect username or press ENTER to refresh:")

def chat_with(name):
    chats.setdefault(name, [])
    while True:
        clear()
        print(f"Chat with {name}\n")
        for m in chats[name]:
            print(m)
        msg = input("\n> ")
        if not msg:
            return
        if len(msg.encode()) > MAX_PAYLOAD:
            continue
        packet = {
            "type": "MESSAGE",
            "SENDER_IP": MY_IP,
            "SENDER_NAME": USERNAME,
            "PAYLOAD": msg
        }
        if name in contacts:
            nc_send(contacts[name], packet)
            chats[name].append(f"You: {msg}")

# ---------- main ----------
USERNAME = input("Enter your username: ").strip()

threading.Thread(target=listener, daemon=True).start()
threading.Thread(target=refresher, daemon=True).start()

while True:
    show_menu()
    choice = input("> ").strip()
    if choice in contacts:
        chat_with(choice)
