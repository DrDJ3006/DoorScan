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
port_protocol_tcp = {1: 'tcpmux', 5: 'rje', 7: 'echo', 9: 'discard', 11: 'systat', 13: 'daytime', 17: 'qotd', 18: 'msp',
                 19: 'chargen', 20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'Telnet', 25: 'smtp', 37: 'time', 39: 'rip',
                 42: 'nameserver', 43: 'nicname', 49: 'tacacs', 50: 're-mail-ck', 53: 'domain', 70: 'gopher',
                 71: 'genius', 79: 'finger', 80: 'http', 81: 'Torpark', 88: 'kerberos', 101: 'hostname',
                 102: 'Iso-tsap', 105: 'csnet-ns', 107: 'rtelnet', 109: 'pop2', 110: 'pop3', 111: 'sunrpc', 115: 'auth',
                 117: 'uucp-path', 119: 'nntp', 123: 'ntp', 137: ' netbios-ns ', 138: 'netbios-dgm', 139: 'netbios-ssn',
                 143: 'imap', 162: 'snmptrap', 177: 'xdmcp', 179: 'bgp', 194: 'irc', 199: 'smux', 201: 'at-rtmp',
                 209: 'qmtp', 210: 'z39.50', 213: 'ipx', 220: 'imap3', 369: 'rpc2portmap', 370: 'codaauth2',
                 389: 'ldap', 427: 'svrloc', 443: 'https', 444: 'snpp', 445: ' microsoft-ds ', 464: 'kpasswd',
                 512: 'exec', 513: 'login', 514: 'shell', 515: 'printer', 530: 'courier',
                 531: 'conference', 532: 'netnews', 540: 'uucp', 543: 'klogin', 544: 'kshell', 547: 'dhcpv6-server',
                 548: 'afpovertcp', 554: 'rtsp', 536: 'nntps', 587: 'submission', 631: 'ipp/cups',
                 636: 'ldaps', 674: 'acap', 694: 'ha-cluster', 749: 'kerberos-adm', 873: 'rsync', 992: 'telnets',
                 993: 'imaps', 995: 'pop3s', 1080: 'socks', 1433: 'ms-sql-s', 1434: 'ms-sql-m', 1494: 'ica',
                 1512: 'wins', 1524: 'ingreslock', 1720: 'h323hostcall', 1812: 'radius', 1813: ' radius-acct ',
                 1985: 'hsrp', 2008: 'Teamspeak 3 Accounting', 2049: 'nfs', 2102: 'zephyr-srv', 2103: 'zephyr-clt',
                 2104: 'zephyr-hm', 2401: 'cvspserver', 2809: 'corbaloc', 3306: ' mysql ', 4321: 'rwhois',
                 5999: 'cvsup', 6000: 'X11', 11371: 'pgpkeyserver', 13720: 'bprd', 13721: 'bpdbm', 13724: 'vnetd',
                 13782: 'bpcd', 13783: 'vopied', 22273: 'wnn6', 23399: 'Skype', 25565: 'Minecraft', 26000: 'quake',
                 33434: 'traceroute'}


# Definition of the function get ping()
def getPing(ip):
    icmp = IP(dst=ip) / ICMP()
    resp = sr1(icmp, timeout=timeout_icmp, verbose=0)
    if resp is None:
        print("[*] (Host Unreachable with ICMP)")


# Definition of the function get getProtocol()
def getProtocol(port):
    protocol = 'unknown'
    for ports in port_protocol_tcp:
        if int(port) == int(ports):
            protocol = port_protocol_tcp[ports]
    return protocol


# Definition of the function get getTime()
def getTime(ip, startingPort, endingPort, timeout, fastscan):
    waiting_time_sc = 0
    waiting_time_min = 0
    waiting_time_hour = 0
    if fastscan == True:
        waiting_time = ceil((int(endingPort) - int(startingPort)) + 1) * timeout + 6
        waiting_time_sc = round(waiting_time % 60)
        waiting_time_min = round(waiting_time // 60)
        if waiting_time_min >= 60:
            waiting_time_hour = round(waiting_time_min // 60)
            waiting_time_min = round(waiting_time_min % 60)
        print("[+] TCP Fast Scan " + ip + ", "+ str(endingPort) + " Ports referenced (≈ waiting " + str(
            waiting_time_hour) + " hour " + str(waiting_time_min) + " min " + str(waiting_time_sc) + " sc)")
    else:
        waiting_time = ceil((int(endingPort) - int(startingPort)) + 1) * timeout + 6
        waiting_time_sc = round(waiting_time % 60)
        waiting_time_min = round(waiting_time // 60)
        if waiting_time_min >= 60:
            waiting_time_hour = round(waiting_time_min // 60)
            waiting_time_min = round(waiting_time_min % 60)
        print("[+] TCP Scanning " + ip + " Port " + str(startingPort) + " to " + str(endingPort) + " (≈ waiting " + str(
            waiting_time_hour) + " hour " + str(waiting_time_min) + " min " + str(waiting_time_sc) + " sc)")


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


def fastPortsScan(portList, ip):
    openPorts = 0
    closedOrFilteredPorts = 0
    portCount = 0
    try:
        for x in portList:
            response = sr1(IP(dst=ip) / TCP(dport=x, flags="S"), verbose=False,
                           timeout=timeout_tcp)  # you can augment the timeout if u have a bad connection
            portCount += 1
            if response:
                try:
                    if response[TCP].flags == 18:
                        print("[*] Open port: " + str(x) + " (" + getProtocol(x) + ")")
                        openPorts += 1
                except IndexError:
                    print("[*] Closed/Filtered port: " + str(x) + " (" + getProtocol(x) + ")")
                    closedOrFilteredPorts += 1
        print("[+] TCP Scan End " + str(portCount) + " port(s) scanned, " + str(openPorts) + " port(s) open, " + str(
            closedOrFilteredPorts) + " port(s) filtered/closed")
    except KeyboardInterrupt:
        print(
            "[+] TCP Scan Stopped " + str(portCount) + " port(s) scanned, " + str(openPorts) + " port(s) open, " + str(
                closedOrFilteredPorts) + " port(s) filtered/closed")
        exit()


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
        print("No parameters selected, use '-h' for help")
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
            print("   - Select the fast scan with '-f' Ex: '... -TCP -t 192.168.1.254 -f'")
            print("   - Select the port range to scan with '-r' Ex: '... -TCP -t 192.168.1.254 -r 1-65535'")
            print("   - Select a single port to scan with '-p' Ex: '... -TCP -t 192.168.1.254 -p 22'")
            print(" UDP (Ports) Scan:")
            print("   - Input '-UDP' (not available for the moment)")
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
                                exit()
                        elif sys.argv[4] == '-p':
                            try:
                                firstPort = int(sys.argv[5])
                                lastPort = int(sys.argv[5])
                            except IndexError:
                                print("[x] Please input a port after '-p' ")
                                exit()
                            except ValueError:
                                print("[x] Please input a port after '-p' ")
                                exit()
                        elif sys.argv[4] == '-f':
                            getPing(target_ip)
                            getTime(target_ip, 1, len(port_protocol_tcp), timeout_tcp, fastscan=True)
                            fastPortsScan(port_protocol_tcp, target_ip)
                            exit()
                        else:
                            print("[x] Unknown parameter(s) '" + str(
                                sys.argv[
                                    4]) + "' use '-p' for scan a single port or '-r' for select a range of ports or '-f' for select the fast scan")
                            exit()
                    except IndexError:
                        firstPort = 1
                        lastPort = 1024
                    getPing(target_ip)
                    getTime(target_ip, firstPort, lastPort, timeout_tcp, fastscan=False)
                    portsScan(firstPort, lastPort, target_ip)
                else:
                    print("[x] Unknown parameter(s) '" + str(sys.argv[2]) + "' use '-t' for input a target")
                    exit()
            except IndexError:
                print("[x] Please input a target with '-t' Ex: '... -t 192.168.1.1'")
                exit()
        elif sys.argv[1] == '-UDP':
            print("[*] UDP scan not available for the moment sry =D")
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
except OSError:
    print("[x] Ip target(s) or network invalid")
    exit()
