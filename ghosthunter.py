# ghosthunter.py
"""
GhostHunter - Aggressive Active Recon / Port + Banner Grabber
GhostDev Systems | Built for real-world target acquisition
"""

import socket
import threading

def scan_target(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors='ignore').strip()
        print(f"[OPEN] {ip}:{port} | Banner: {banner if banner else 'No banner'}")
        sock.close()
    except:
        pass

def launch_scan(ip):
    print(f"\n[+] Scanning Target: {ip}")
    for port in range(1, 1025):  # Flex up to 1024
        thread = threading.Thread(target=scan_target, args=(ip, port))
        thread.start()

if __name__ == "__main__":
    target = input("Target IP: ").strip()
    launch_scan(target)
