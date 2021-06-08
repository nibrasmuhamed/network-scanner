#!/usr/bin/env python
# Network scan using scapy.
#
# This python script using scapy module will scan your network and returns all the clients
# within the network.
#
# this script should run with python 2.7 or python 3. any way you need to install dependencies
# for curresponding version
#
# you need two dependencies to run:
#   1.scapy
#   2.colorama
#
#          code contributed by: @nibrasmuhamed on Github
#                       @nibras_muhamed on Instagram
#
#
import scapy.all as scapy
import argparse


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t", dest="target",  help="Enter your gateway with subnet(for eg:192.168.1.1/24)")
    option = parser.parse_args()
    return option


def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    answered_lst = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    print(answered_lst.summary())
    client_list = []

    for packet in answered_lst:
        client_dic = {"ip": packet[1].psrc, "mac": packet[1].hwsrc}
        client_list.append(client_dic)

    return client_list


def print_all(result_list):
    print("IP Address\t\t\tMac Adress\n---------------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


option = get_args()
scan_res = scan(option.target)
print_all(scan_res)
