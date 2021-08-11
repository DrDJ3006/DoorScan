#!/usr/bin/python3
from scapy.all import *
from os import system, name
from math import *

target_ip = 0
target_network = 0
target_network_ip = 0
target_network_mask = 0
ports = 0
firstPort = 0
lastPort = 0
network_ip = 0
timeout_icmp = 3  # you can change the timeouts if u have a good or a bad connection
timeout_tcp = 0.2
timeout_arp = 7
# creation and initialization of the list of protocols with their associated ports for the getPort() function
port_protocol = {20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'Telnet', 25: 'smtp', 53: 'dns', 67: 'DHCP-Client',
                 68: 'DHCP-Server', 69: 'tftp', 80: 'http', 110: 'pop3', 123: 'ntp', 137: 'netbios-ns', 143: 'imap4',
                 161: 'snmp', 162: 'snmp-trap', 389: 'ldap', 443: 'https', 445: 'cifs', 546: 'dhcp_v6', 993: 'imaps',
                 995: 'pop3s', 1433: 'Microsoft SQL Server', 1521: 'Oracle SQL', 3306: 'MySQL', 5432: 'PostgreSQL',
                 5900: 'VNC-Server', 6667: 'irc'}


# Definition of the function get ping()
def getPing(ip):
    icmp = IP(dst=ip) / ICMP()
    resp = sr1(icmp, timeout=timeout_icmp, verbose=0)
    if resp is None:
        print("[*] (Host Unreachable with ICMP)")


# Definition of the function get getProtocol()
def getProtocol(port):
    protocol = 'unknown'
    for ports in port_protocol:
        if int(port) == int(ports):
            protocol = port_protocol[ports]
    return protocol


# Definition of the function get getTime()
def getTime(startingPort, endingPort, timeout):
    waiting_time_min = 0
    waiting_time_sc = 0
    waiting_time_hour = 0
    waiting_time = ceil(timeout * (int(endingPort) - int(startingPort)))
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
        print("[+] TCP Scanning " + target_ip + " port " + str(startingPort) + " to " + str(endingPort) + " (≈ " + str(
            waiting_time_hour) + "h " + str(waiting_time_min) + "min " + str(waiting_time_sc) + "sc waiting)")
    except NameError:
        print("[+] TCP Scanning " + target_ip + " port " + str(startingPort) + " to " + str(endingPort) + " (≈ " + str(
            waiting_time_min) + "min " + str(waiting_time_sc) + "sc waiting)")


# Definition of the function get portsScan()
def portsScan(startingPort, endingPort, ip):
    openPorts = 0
    closedOrFilteredPorts = 0
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
                    closedOrFilteredPorts += 1
            portScanning += 1
        print("[+] TCP Scan End " + str(portCount) + " port(s) scanned, " + str(openPorts) + " port(s) open, " + str(
            closedOrFilteredPorts) + " port(s) filtered/closed")
    except KeyboardInterrupt:
        print("\n[x] Ctrl + C Pressed, Exiting")
        print(
            "[+] TCP Scan Stopped " + str(portCount) + " port(s) scanned, " + str(openPorts) + " port(s) open, " + str(
                closedOrFilteredPorts) + " port(s) filtered/closed")


def ArpRequest(ip, timeout):
    target = ip
    target_ip = target.split('/')
    target_ip_bytes = target_ip[0].split('.')
    if target_ip_bytes[3] == '255':
        print("[x] A single target cannot end by a 255")
        exit()
    if target_ip_bytes[3] == '0':
        print("[*] (A target ending with a 0 may not respond)")
    print("[+] ARP Request " + str(target_ip[0]))
    arp_r = ARP(pdst=target_ip)
    br = Ether(dst='ff:ff:ff:ff:ff:ff')
    request = br / arp_r
    answered, unanswered = srp(request, timeout=timeout, verbose=0)
    for i in answered:
        print("[*] " + i[1].psrc + "  <=====>  " + i[1].hwsrc.upper())
    if str(len(answered)) == '1':
        print("[+] ARP Request End, " + str(len(answered)) + " response(s) received from " + str(target_ip[0]))
    else:
        print("[x] ARP Request End, no response(s) received from " + str(target_ip[0]))


def ArpScan(network, timeout):
    try:
        network_ip, mask = network.split('/')
    except ValueError:
        print("[x] Please input a mask 'X.X.X.0/mask'")
        exit()
    network_ip_bytes = network_ip.split(".")
    if network_ip_bytes[3] != '0':
        print("[x] The network must end by a 0 'X.X.X.0/mask'")
        exit()
    print("[+] ARP Scanning Network " + network)
    arp_r = ARP(pdst=network)
    br = Ether(dst='ff:ff:ff:ff:ff:ff')
    request = br / arp_r
    answered, unanswered = srp(request, timeout=timeout, verbose=0)
    for i in answered:
        print("[*] " + i[1].psrc + "  <=====>  " + i[1].hwsrc.upper())
    if str(len(answered)) >= '1':
        print("[+] ARP Request End, " + str(len(answered)) + " response(s) received from " + str(network))
    else:
        print("[x] ARP Request End, no response(s) received from " + str(network))


try:
    if len(sys.argv) < 2:
        print("No parameters selected, type '" + sys.argv[0] + " -h' for help")
        exit()
    else:
        if sys.argv[1] == '-h':
            print("[*] Help")
            print(" ICMP Scan:")
            print("   - Input '-ICMP' (not available for the moment)")
            print(" ARP Scan:")
            print("   - Input '-ARP'")
            print("   - Select a network to scan with '-n' Ex: '... -ARP -n 192.168.1.0/24'")
            print("   - Select a single target to request with '-t' Ex: '... -ARP -t 192.168.1.254'")
            print(" TCP (Ports) Scan:")
            print("   - Input '-TCP'")
            print(
                "   - Select a target to scan with '-t' Ex: '... -TCP -t 192.168.1.254' (default port scan 1 to 1024) ")
            print("   - Select the port range to scan with '-r' Ex: '... -TCP -t 192.168.1.254 -r 1-65535'")
            print("   - Select a single port to scan with '-p' Ex: '... -TCP -t 192.168.1.254 -p 22'")
            exit()
        elif sys.argv[1] == '-ICMP':
            print("[*] ICMP scan not available for the moment sry =D")
            exit()
        elif sys.argv[1] == '-ARP':
            try:
                if sys.argv[2] == '-n':
                    try:
                        target_network = sys.argv[3]
                        target_network_ip, target_network_mask = target_network.split('/', maxsplit=1)
                        ArpScan(target_network, timeout_arp)
                    except ValueError:
                        print("[x] Please input a mask for the network Ex: '... -n 192.168.1.0/24'")
                        exit()
                elif sys.argv[2] == '-t':
                    target_ip = sys.argv[3]
                    ArpRequest(target_ip, timeout_arp)
                else:
                    print("[x] Unknown parameter(s) '" + str(
                        sys.argv[2]) + "' use '-n' for input a network or a target with '-t'")
                    exit()
            except IndexError:
                print("[x] Please input a network with '-n' or a target with '-t' Ex : '... -t/-n 192.168.0.1/24'")
                exit()
        elif sys.argv[1] == '-TCP':
            try:
                if sys.argv[2] == '-t':
                    target_ip = sys.argv[3]
                    try:
                        if sys.argv[4] == '-r':
                            try:
                                ports = sys.argv[5].split('-', maxsplit=1)
                                firstPort = int(ports[0])
                                lastPort = int(ports[1])
                            except IndexError:
                                print("[x] Please input a port range after '-r' format: '1-65535' (scanning port 1 to "
                                      "65535)")
                        elif sys.argv[4] == '-p':
                            try:
                                firstPort = int(sys.argv[5])
                                lastPort = int(sys.argv[5])
                            except IndexError:
                                print("[x] Please input a port after '-p' ")
                    except IndexError:
                        firstPort = 1
                        lastPort = 1024
                    getPing(target_ip)
                    getTime(firstPort, lastPort, timeout_tcp)
                    portsScan(firstPort, lastPort, target_ip)
                else:
                    print("[x] Unknown parameter(s) '" + str(sys.argv[2]) + "' use '-t' for input a target")
                    exit()
            except IndexError:
                print("[x] Please input a target with '-t' Ex: '... -t 192.168.1.1'")
                exit()
        else:
            print("[x] Unknown parameter(s) '" + str(sys.argv[1]) + "' use '-h' for help")
            exit()
except PermissionError:
    print("[x] Please run the script as root")
    exit()
except socket.gaierror:
    print("[x] Ip target(s) or network invalid")
    exit()
