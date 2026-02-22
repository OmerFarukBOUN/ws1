#!/usr/bin/env python3
import subprocess
import threading
import json
import time
import os
import socket
import sys
import select

PORT = 12487
MAX_PAYLOAD = 2048
REFRESH_INTERVAL = 10

contacts = {}   # name -> ip (last known)
online = {}     # name -> ip (current scan)
chats = {}      # name -> [messages]
lock = threading.Lock()

BOLD = "\033[1m"
RED = "\033[31m"
RESET = "\033[0m"

def clear():
    os.system("clear")

# ---------- network ----------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("192.168.1.1", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

MY_IP = get_local_ip()
SUBNET = ".".join(MY_IP.split(".")[:3])

# ---------- netcat ----------
def start_listener():
    return subprocess.Popen(
        ["nc", "-l", "-p", str(PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

def nc_send(ip, packet):
    try:
        p = subprocess.Popen(
            ["nc", ip, str(PORT)],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True
        )
        p.communicate(json.dumps(packet) + "\n", timeout=1)
    except:
        pass

# ---------- protocol ----------
def broadcast_ask():
    pkt = {
        "type": "ASK",
        "SENDER_IP": MY_IP
    }
    for i in range(1, 255):
        ip = f"{SUBNET}.{i}"
        if ip != MY_IP:
            nc_send(ip, pkt)

def handle_packet(pkt):
    if pkt["type"] == "ASK":
        reply = {
            "type": "REPLY",
            "RECEIVER_NAME": USERNAME,
            "RECEIVER_IP": MY_IP
        }
        nc_send(pkt["SENDER_IP"], reply)

    elif pkt["type"] == "REPLY":
        name = pkt["RECEIVER_NAME"]
        ip = pkt["RECEIVER_IP"]
        with lock:
            online[name] = ip
            contacts.setdefault(name, ip)

    elif pkt["type"] == "MESSAGE":
        name = pkt["SENDER_NAME"]
        chats.setdefault(name, []).append(f"{name}: {pkt['PAYLOAD']}")

# ---------- threads ----------
def listener_loop(proc):
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        try:
            pkt = json.loads(line.strip())
            handle_packet(pkt)
        except:
            pass

def refresher():
    while True:
        with lock:
            online.clear()
        broadcast_ask()
        time.sleep(REFRESH_INTERVAL)

# ---------- UI ----------
def show_menu():
    clear()
    print(f"{USERNAME} @ {MY_IP}\n")
    for name, ip in contacts.items():
        if name in online:
            print(f"{BOLD}{name}{RESET}")
        elif ip != contacts[name]:
            print(f"{RED}{name}{RESET}")
        else:
            print(name)
    print("\nSelect user or ENTER to refresh:")

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
        pkt = {
            "type": "MESSAGE",
            "SENDER_IP": MY_IP,
            "SENDER_NAME": USERNAME,
            "PAYLOAD": msg
        }
        if name in contacts:
            nc_send(contacts[name], pkt)
            chats[name].append(f"You: {msg}")

# ---------- main ----------
USERNAME = input("Username: ").strip()

listener_proc = start_listener()
threading.Thread(target=listener_loop, args=(listener_proc,), daemon=True).start()
threading.Thread(target=refresher, daemon=True).start()

while True:
    show_menu()
    choice = input("> ").strip()
    if choice in contacts:
        chat_with(choice)
