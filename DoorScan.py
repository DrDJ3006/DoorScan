#!/usr/bin/python3
import logging
from scapy.all import *
from os import system, name
from math import *

timeout_icmp = 3
timeout_tcp = 0.2
port_protcol = {20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'Telnet', 25: 'smtp', 53: 'dns', 67: 'DHCP-Client',
                68: 'DHCP-Server', 69: 'tftp', 80: 'http', 110: 'pop3', 123: 'ntp', 137: 'netbios-ns', 143: 'imap4',
                161: 'snmp', 162: 'snmp-trap', 389: 'ldap', 443: 'https', 445: 'cifs', 546: 'dhcp_v6', 993: 'imaps',
                995: 'pop3s', 1433: 'Microsoft SQL Server', 1521: 'Oracle SQL', 3306: 'MySQL', 5432: 'PostgreSQL',
                5900: 'VNC-Server', 6667: 'irc'}


def getPing():
    icmp = IP(dst=target_ip) / ICMP()
    resp = sr1(icmp, timeout=timeout_icmp, verbose=0)  # you can augment the timeout if u have a bad connection
    if resp == None:
        print("[*] (Host Unreachable with ICMP)")


def getProtocol(port):
    protocol = 'unknown'
    for ports in port_protcol:
        if int(port) == int(ports):
            protocol = port_protcol[ports]
    return protocol


def getTime(timeout):
    waiting_time = ceil((timeout * 1.5) * (scale - port))
    if waiting_time / 3600 < 1:
        waiting_time_min = round(waiting_time / 60, 2)
        waiting_time_sc = round(round(waiting_time_min - round(waiting_time_min), 2) * 60)
        waiting_time_min = round(waiting_time_min)
    else:
        waiting_time_hour = round(waiting_time / 3600, 2)
        waiting_time_min = round(waiting_time_hour - round(waiting_time_hour), 2) * 60
        waiting_time_sc = round(round(waiting_time_min - round(waiting_time_min), 2) * 60)
        waiting_time_hour = round(waiting_time_hour)
        waiting_time_min = round(waiting_time_min)
    try:
        print("[+] TCP Scanning " + target_ip + " port " + str(port) + " to " + str(scale) + " (≈ " + str(
            waiting_time_hour) + "h " + str(waiting_time_min) + "min " + str(waiting_time_sc) + "sc waiting)")
    except NameError:
        print("[+] TCP Scanning " + target_ip + " port " + str(port) + " to " + str(scale) + " (≈ " + str(
            waiting_time_min) + "min " + str(waiting_time_sc) + "sc waiting)")


def portsScan(startingPort, endingPort, ip):
    openPorts = 0
    UnknownPorts = 0
    portCount = 0
    portScanning = startingPort
    try:
        while portScanning <= endingPort:
            response = sr1(IP(dst=ip) / TCP(dport=portScanning, flags="S"), verbose=False,
                           timeout=timeout_tcp)  # you can augment the timeout if u have a bad connection
            portCount += 1
            if response:
                try:
                    if response[TCP].flags == 18:
                        print("[*] Open port: " + str(portScanning) + " (" + getProtocol(portScanning) + ")")
                        openPorts += 1
                except IndexError:
                    print("[*] Closed/Filtered port: " + str(portScanning) + " (" + getProtocol(portScanning) + ")")
                    UnknownPorts += 1
            portScanning += 1
        print("[+] TCP Scan End " + str(portCount) + " port(s) scanned, " + str(openPorts) + " port(s) open, " + str(
            UnknownPorts) + " port(s) filtered/closed")
    except KeyboardInterrupt:
        print("\n[x] Ctrl + C Pressed, Exiting")
        print("[+] TCP Scan Stopped " + str(portCount) + " port(s) scanned, " + str(openPorts) + " port(s) open, " + str(
            UnknownPorts) + " port(s) filtered/closed")


if len(sys.argv) < 2:
    print("No parameters selected, type '" + sys.argv[0] + " -h' for help")
    exit()
else:
    if sys.argv[1] == "-t":
        try:
            target_ip = sys.argv[2]
        except IndexError:
            print("[x] Please select a target")
            exit()
    elif sys.argv[1] == "-h":
        print("[+] help list :")
        print("[*] -t for select the target")
        print("[*] -r for select the range of ports")
        print("[*] Ex: PortsScan -t 192.168.1.254 (default range 1 to 1024)")
        print("[*] Ex: PortsScan -t 192.168.1.254 -r 22 (u can use a single port)")
        print("[*] Ex: PortsScan -t 192.168.1.254 -r 1-65535 (it could take a while ...)")
        exit()
    else:
        print("[x] Unknown parameter(s) '" + str(sys.argv[1]) + "' use '-h' for help")
        exit()
    if len(sys.argv) > 3:
        try:
            if sys.argv[3] == "-r":
                ports = sys.argv[4].split('-', maxsplit=1)
                if int(ports[0]) < 1:
                    print("[x] starting port range cannot be under 0")
                    exit()
                elif int(ports[1]) > 65535:
                    print("[x] last port range cannot be over 65535")
                    exit()
                else:
                    port = int(ports[0])
                    scale = int(ports[1])
            else:
                print("[x] Unknown parameter(s) '" + str(sys.argv[1]) + "' use '-h' for help")
                exit()
        except IndexError as e:
            try:
                port = int(ports[0])
                scale = int(ports[0])
            except NameError as e:
                print("[x] Please select a range")
                exit()
    else:
        port = 1
        scale = 1024

try:
    getPing()
    getTime(timeout_tcp)
    portsScan(port, scale, target_ip)

except PermissionError:
    print("[x] Please run the script as root")
    exit()
except socket.gaierror:
    print("[x] Ip target invalid")
    exit()
