import os
import sys
import time
from collections import defaultdict
from scapy.layers.inet import IP, TCP
from scapy.all import sniff

threshold = 40
print(f"Threshold: {threshold}")

#Read IPs from a file
def readIPFile(fileName):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips)

# Check for Nimda worm signature
def nimdaWorm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        return "Get /scripts/root.exe" in str(payload)
    return false

# Log events
def logEvent(Message):
    logFolder = "logs"
    os.makedirs(logFolder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    logFile = os.path.join(logFolder, f"log_{timestamp}.txt")

    with open(logFile, "a") as file:
        file.write(f"{message}\n")

def packetCallback(packet):
    sourceIP = packet[IP].src

    # Check if IP is in the whitelist
    if sourceIP in whitelistIPs:
        return

    # Check if IP is in the blacklist
    if sourceIP in blacklistIPs:
        os.system(f"iptables -A INPUT -s {sourceIP} -j DROP")
        logEvent(f"Blocking blacklisted IP: {sourceIP}")
        return

    if nimdaWorm(packet):
        print(f"Blocking Nimda source IP: {sourceIP}")
        os.system(f"iptables -A INPUT -s {sourceIP} -j DROP")
        logEvent(f"Blocking Nimda source IP: {sourceIP}")
        return

    packetCount[sourceIP] += 1

    currentTime = time.time()
    timeInterval = currentTime - startTime[0]

    if timeInterval >= 1:
        for ip, count in packetCount.items():
            packetRate = count / timeInterval

            if packetRate > Threshold and IP not in blockedIPs:
                print(f"Blocing IP: {ip}\n" + f"Packet Rate: {packetRate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                logEvent(f"Blocking IP: {ip}\n" + f"Packet Rate: {packetRate}")
                blockedIPs.add(ip)

        packetCount.clear()
        startTime[0] = currentTime

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

        # Import whitelist and blacklist IPs

        whitelistIPs = readIPFile("whitelist.txt")
        blacklistIPs = readIPFile("blacklist.txt")

        packetcount = defaultdict(int)
        startTime = [time.time()]
        blockedIPs = set()

        print("Monitoring Network Traffic...")
        sniff(filter="ip", prn=packetCallback())










