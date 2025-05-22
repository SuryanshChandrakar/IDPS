from scapy.all import sniff, IP, TCP, UDP, ICMP
import redis
import subprocess
from collections import defaultdict
import time

# --- CONFIG ---
YOUR_SERVER_IP = "192.168.224.170"
APP_PORT = 5000

# Thresholds for detection
THRESHOLDS = {
    "SYN": 100,
    "UDP": 200,
    "ICMP": 150,
    "FRAG": 20,
    "TCP": 100,
    "Smurf": 50,
}

# Redis setup
r = redis.Redis(host='localhost', port=6379, db=0)
attack_counts = defaultdict(lambda: defaultdict(int))      # Packet count
last_uploaded_counts = defaultdict(lambda: defaultdict(int))  # Track last uploaded value
BLOCKED_IPS = set()

# Upload threshold values once at start
r.hmset("thresholds", THRESHOLDS)

def log_to_redis(ip, attack_type, count):
    # Upload only if count increased
    if count != last_uploaded_counts[ip][attack_type]:
        timestamp = int(time.time())
        redis_key = f"graph_data:{attack_type}"
        r.rpush(redis_key, f"{timestamp},{count}")
        r.ltrim(redis_key, -300, -1)
        last_uploaded_counts[ip][attack_type] = count

def mark_block_event(ip, attack_type):
    timestamp = int(time.time())
    redis_key = f"graph_data:{attack_type}"
    r.rpush(redis_key, f"{timestamp},0")
    r.ltrim(redis_key, -300, -1)

    # Store block info
    r.hmset(f"blocked_info:{ip}", {
        "type": attack_type,
        "time": timestamp
    })

def block_ip(ip, attack_type):
    if ip not in BLOCKED_IPS:
        print(f"[!] Blocking IP: {ip}")
        r.sadd("blocked_ips", ip)

        subprocess.run([
            "powershell.exe",
            "-Command",
            f"New-NetFirewallRule -DisplayName Block_IN_{ip} -Direction Inbound -RemoteAddress {ip} -Action Block -Profile Any"
        ])

        subprocess.run([
            "powershell.exe",
            "-Command",
            f"New-NetFirewallRule -DisplayName Block_OUT_{ip} -Direction Outbound -RemoteAddress {ip} -Action Block -Profile Any"
        ])

        mark_block_event(ip, attack_type)
        BLOCKED_IPS.add(ip)

def unblock_all():
    for ip in r.smembers("blocked_ips"):
        ip_str = ip.decode()
        print(f"[!] Unblocking IP: {ip_str}")

        subprocess.run([
            "powershell.exe",
            "-Command",
            f"Remove-NetFirewallRule -DisplayName Block_IN_{ip_str}"
        ])
        subprocess.run([
            "powershell.exe",
            "-Command",
            f"Remove-NetFirewallRule -DisplayName Block_OUT_{ip_str}"
        ])

        r.srem("blocked_ips", ip)
        BLOCKED_IPS.discard(ip_str)

def detect_attack(pkt):
    if IP not in pkt:
        return

    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    ip_flags = pkt[IP].flags

    # Skip if from a blocked IP
    if ip_src in BLOCKED_IPS:
        return

    if ip_dst != YOUR_SERVER_IP:
        return

    # TCP SYN Flood
    if TCP in pkt and pkt[TCP].dport == APP_PORT:
        flags = pkt[TCP].flags

        if flags == 'S':
            attack_counts[ip_src]["SYN"] += 1
            count = attack_counts[ip_src]["SYN"]
            log_to_redis(ip_src, "SYN", count)
            if count > THRESHOLDS["SYN"]:
                block_ip(ip_src, "SYN")
        else:
            attack_counts[ip_src]["TCP"] += 1
            count = attack_counts[ip_src]["TCP"]
            log_to_redis(ip_src, "TCP", count)
            if count > THRESHOLDS["TCP"]:
                block_ip(ip_src, "TCP")

    elif UDP in pkt and pkt[UDP].dport == APP_PORT:
        attack_counts[ip_src]["UDP"] += 1
        count = attack_counts[ip_src]["UDP"]
        log_to_redis(ip_src, "UDP", count)
        if count > THRESHOLDS["UDP"]:
            block_ip(ip_src, "UDP")

    elif ICMP in pkt:
        if pkt[ICMP].type == 8:
            attack_counts[ip_src]["ICMP"] += 1
            count = attack_counts[ip_src]["ICMP"]
            log_to_redis(ip_src, "ICMP", count)

            if ip_dst.endswith(".255") and ip_src != YOUR_SERVER_IP:
                attack_counts[ip_src]["Smurf"] += 1
                if attack_counts[ip_src]["Smurf"] > THRESHOLDS["Smurf"]:
                    block_ip(ip_src, "Smurf")

            if count > THRESHOLDS["ICMP"]:
                block_ip(ip_src, "ICMP")

    if pkt[IP].frag > 0 or (ip_flags & 0x1):
        attack_counts[ip_src]["FRAG"] += 1
        count = attack_counts[ip_src]["FRAG"]
        log_to_redis(ip_src, "FRAG", count)
        if count > THRESHOLDS["FRAG"]:
            block_ip(ip_src, "FRAG")

    print(f"[{time.strftime('%X')}] Packet from {ip_src} -> {ip_dst} | Counts: {dict(attack_counts[ip_src])}")

print(f"[*] Monitoring attacks to {YOUR_SERVER_IP}:{APP_PORT}... Press Ctrl+C to stop and unblock IPs.")

try:
    sniff(
        filter="ip",
        prn=detect_attack,
        store=0
    )
except KeyboardInterrupt:
    print("\n[!] Interrupted. Cleaning up...")
finally:
    unblock_all()
    print("[+] All firewall rules removed. Exiting.")
