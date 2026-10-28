import os
import sys
import time
from collections import defaultdict
from scapy.layers.inet import IP, TCP    # Scapy is used for packet capture/inspection
from scapy.all import sniff


# Packet rate threshold to identify abnormal traffic volumes
threshold = 40
print(f"Threshold: {threshold}")

""" Reads IP addresses from a file and stores them in a set.
This will enhance the processes blacklist/whitelist checks """

def readIPFile(fileName):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips)

""" This function is to detect a known Nimda worm attack signiture """

def nimdaWorm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80: # Checks if the packet has a TCP layer
        payload = packet[TCP].payload # Extracts the packets payload (information)
        return "Get /scripts/root.exe" in str(payload) # Compares the payload against a known malicious pattern.
        # If the string above is found, the script will return 'true' which indicates an attack attempt """
    
    return false

# Log events
def logEvent(Message):
    logFolder = "logs"
    os.makedirs(logFolder, exist_ok=True)    # Creating the folder if it doesn't already exist
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    logFile = os.path.join(logFolder, f"log_{timestamp}.txt") # Using the timestamp, create unique file name

    with open(logFile, "a") as file:
        file.write(f"{message}\n") # Writing the message within the file 

def packetCallback(packet):
    sourceIP = packet[IP].src # Extracting source IP address from captured packet

    # Check if IP is in the whitelist
    if sourceIP in whitelistIPs:
        return

    # Check if IP is in the blacklist
    if sourceIP in blacklistIPs:
        os.system(f"iptables -A INPUT -s {sourceIP} -j DROP") # Adds firewall rule to drop incoming traffic from IP
        logEvent(f"Blocking blacklisted IP: {sourceIP}") # Records the event within the log file
        return
        
    # Checks if packet has attack signature
    if nimdaWorm(packet):
        print(f"Blocking Nimda source IP: {sourceIP}")
        os.system(f"iptables -A INPUT -s {sourceIP} -j DROP") # Adds firewall rule to drop incoming traffic from IP
        logEvent(f"Blocking Nimda source IP: {sourceIP}") # Records the event within the log file
        return

    packetCount[sourceIP] += 1 # Packet counter

    currentTime = time.time()
    timeInterval = currentTime - startTime[0]

    if timeInterval >= 1:
        for ip, count in packetCount.items(): # Checks the packet count for each IP
            packetRate = count / timeInterval

            """If the packet rate exceeds the threshold and the IP hasn't been blocked,
            a firewall rule has been added to drop the traffic correlating to the IP address"""
            
            if packetRate > Threshold and IP not in blockedIPs:
                print(f"Blocking IP: {ip}\n" + f"Packet Rate: {packetRate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                logEvent(f"Blocking IP: {ip}\n" + f"Packet Rate: {packetRate}")
                blockedIPs.add(ip) # Add ip to block list

        packetCount.clear()
        startTime[0] = currentTime

if __name__ == "__main__":
    if os.geteuid() != 0: # Ensuring it is being executed with root priveleges
        print("This script requires root privileges.")
        sys.exit(1)

        # Import whitelist and blacklist IPs

        whitelistIPs = readIPFile("whitelist.txt")
        blacklistIPs = readIPFile("blacklist.txt")

        packetcount = defaultdict(int)
        startTime = [time.time()]
        blockedIPs = set()

        print("Monitoring Network Traffic...")
        sniff(filter="ip", prn=packetCallback()) # Begin capturing network traffic
        # Sends each packet to the callback function for inspection


""" Credit to AIONSEC on YouTube for the walkthrough """







