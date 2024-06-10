#!/usr/bin/python3
#_*_ coding: utf8 *_*

import argparse
import scapy.all as scapy

parser = argparse.ArgumentParser(description="red scan ARP")
parser.add_argument('-r','--range',help="Insert ip range")
parser = parser.parse_args()

def main():
    if parser.range:
        ip_scan(parser.range)
    else:
        print("Write the required parameters")

def ip_scan(ip):
    range_ip = scapy.ARP(pdst=ip)
    # Vamos a trabajar en la capa 3
    broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast/range_ip
    # Enviamos el paquete en capa 3
    res = scapy.srp(final_packet,timeout=2,verbose=False)[0]
    for item in res:
        print(f"[+] HOST: {item[1].psrc}  MAC: {item[1].hwsrc}")
try:
    main()
except:
    print("Permission Denied Using Sudo")
    exit()