#!/usr/bin/python3
try:
    from scapy.all import *
    from os import system, name
    from math import *
    from ipaddress import *
    import random
    import socket
except ModuleNotFoundError:
    print("[x] Error of module please launch 'pip3 install -r requirements.txt'")
    exit("[*] If you find any problems,errors or bugs please contact me at 'https://github.com/DrDJ3006'")

self_ip = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][0]
target_ip = 0
target_network = 0
target_network_ip = 0
target_network_ip_bytes = 0
target_network_mask = 0
ports = 0
firstPort = 0
lastPort = 0
network_ip = 0
# you can change the timeouts if u have a good or a bad connection
timeout_icmp = 0.2
timeout_tcp = 0.2
timeout_arp = 5
# creation and initialization of the list of protocols with their associated ports for the getPort() function
port_protocol_tcp = {1: 'tcpmux', 5: 'rje', 7: 'echo', 9: 'discard', 11: 'systat', 13: 'daytime', 17: 'qotd', 18: 'msp',
                     19: 'chargen', 20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'Telnet', 25: 'smtp', 37: 'time',
                     39: 'rip',
                     42: 'nameserver', 43: 'nicname', 49: 'tacacs', 50: 're-mail-ck', 53: 'domain', 70: 'gopher',
                     71: 'genius', 79: 'finger', 80: 'http', 81: 'Torpark', 88: 'kerberos', 101: 'hostname',
                     102: 'Iso-tsap', 105: 'csnet-ns', 107: 'rtelnet', 109: 'pop2', 110: 'pop3', 111: 'sunrpc',
                     115: 'auth',
                     117: 'uucp-path', 119: 'nntp', 123: 'ntp', 137: ' netbios-ns ', 138: 'netbios-dgm',
                     139: 'netbios-ssn',
                     143: 'imap', 162: 'snmptrap', 177: 'xdmcp', 179: 'bgp', 194: 'irc', 199: 'smux', 201: 'at-rtmp',
                     209: 'qmtp', 210: 'z39.50', 213: 'ipx', 220: 'imap3', 369: 'rpc2portmap', 370: 'codaauth2',
                     389: 'ldap', 427: 'svrloc', 443: 'https', 444: 'snpp', 445: ' microsoft-ds ', 464: 'kpasswd',
                     512: 'exec', 513: 'login', 514: 'shell', 515: 'printer', 530: 'courier',
                     531: 'conference', 532: 'netnews', 540: 'uucp', 543: 'klogin', 544: 'kshell', 547: 'dhcpv6-server',
                     548: 'afpovertcp', 554: 'rtsp', 536: 'nntps', 587: 'submission', 631: 'ipp/cups',
                     636: 'ldaps', 674: 'acap', 694: 'ha-cluster', 749: 'kerberos-adm', 873: 'rsync', 992: 'telnets',
                     993: 'imaps', 995: 'pop3s', 1080: 'socks', 1287: 'routematch', 1433: 'ms-sql-s', 1434: 'ms-sql-m',
                     1494: 'ica',
                     1512: 'wins', 1524: 'ingreslock', 1720: 'h323hostcall', 1812: 'radius', 1813: ' radius-acct ',
                     1985: 'hsrp', 2008: 'Teamspeak 3 Accounting', 2049: 'nfs', 2102: 'zephyr-srv', 2103: 'zephyr-clt',
                     2104: 'zephyr-hm', 2401: 'cvspserver', 2809: 'corbaloc', 3306: ' mysql ', 4321: 'rwhois',
                     5999: 'cvsup', 6000: 'X11', 11371: 'pgpkeyserver', 13720: 'bprd', 13721: 'bpdbm', 13724: 'vnetd',
                     13782: 'bpcd', 13783: 'vopied', 22273: 'wnn6', 23399: 'Skype', 25565: 'Minecraft', 26000: 'quake',
                     27017: 'MongoDB', 33434: 'traceroute'}


def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc


# Definition of the function get ping()
def getPing(ip):
    if ip_address(self_ip) in ip_network(ip, strict=False):
        ip_to_request, mask = ip.split('/', maxsplit=1)
        try:
            if get_mac(ip_to_request):
                return ip_to_request
        except IndexError:
            exit("[x] Target '" + ip_to_request + "' is unreachable in your local network")
    else:
        icmp = IP(dst=ip) / ICMP()
        resp = sr1(icmp, timeout=timeout_icmp, verbose=0)
        if resp is None:
            print("[*] (Host Unreachable with ICMP)")
    return ip


# Definition of the function get getProtocol()
def getProtocol(port):
    protocol = 'unknown'
    for ports in port_protocol_tcp:
        if int(port) == int(ports):
            protocol = port_protocol_tcp[ports]
    return protocol


# Definition of the function get getTime()
def getHead(protocol, ip, startingPortHost, endingPortHost, timeout, fastscan, typeOfTarget):
    waiting_time_sc = 0
    waiting_time_min = 0
    waiting_time_hour = 0
    waiting_time = ceil((int(endingPortHost) - int(startingPortHost)) + 1) * timeout + 4
    waiting_time_sc = round(waiting_time % 60)
    waiting_time_min = round(waiting_time // 60)
    if waiting_time_min >= 60:
        waiting_time_hour = round(waiting_time_min // 60)
        waiting_time_min = round(waiting_time_min % 60)

    if fastscan == True and protocol == 'TCP':
        print(
            "[+] TCP Fast Scan " + ip + ", " + str(endingPortHost) + " Ports referenced (≈ waiting " + str(
                waiting_time_hour) + " hour " + str(waiting_time_min) + " min " + str(waiting_time_sc) + " sc)")
    elif protocol == 'TCP':
        print("[+] TCP Scanning " + ip + " Port " + str(startingPortHost) + " to " + str(
            endingPortHost) + " (≈ waiting " + str(
            waiting_time_hour) + " hour " + str(waiting_time_min) + " min " + str(waiting_time_sc) + " sc)")
    elif protocol == 'ICMP':
        print("[+] ICMP Scanning " + ip + ", " + str(endingPortHost) + " Hosts to scan (≈ waiting " + str(
            waiting_time_hour) + " hour " + str(waiting_time_min) + " min " + str(waiting_time_sc) + " sc)")
    elif protocol == 'ARP':
        if typeOfTarget == 'network':
            netwok = ip_network(ip)
            print("[+] ARP Scanning network " + str(netwok) + " (≈ waiting " + str(
                waiting_time_hour) + " hour " + str(waiting_time_min) + " min " + str(waiting_time_sc) + " sc)")
        elif typeOfTarget == 'target':
            print("[+] ARP request " + str(ip) + " (≈ waiting " + str(
                waiting_time_hour) + " hour " + str(waiting_time_min) + " min " + str(waiting_time_sc) + " sc)")
    else:
        exit("[x] Error coding unknown protocol")


def pingScan(network, timeout):
    try:
        addresses = IPv4Network(network)
        hostsUp = 0
        blockedHosts = 0
        scannedHosts = 0
        getHead('ICMP', network, 0, addresses.num_addresses, timeout_icmp, False, 'network')
        for host in addresses:
            if host in (addresses.network_address, addresses.broadcast_address):
                pass
            resp = sr1(IP(dst=str(host)) / ICMP(), timeout=timeout, verbose=0, )
            if resp is None:
                pass
            elif int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                print(f"[*] Host blocking ICMP: {host}")
                blockedHosts += 1
            else:
                print(f"[*] Host responding: {host}")
                hostsUp += 1
            scannedHosts += 1
        print("[+] ICMP Scan End " + str(scannedHosts) + " host(s) scanned on " + network + ", " + str(
            hostsUp) + " host(s) up, " + str(
            blockedHosts) + " host(s) blocking ICMP")
    except KeyboardInterrupt:
        exit("[+] ICMP Scan Stopped " + str(scannedHosts) + " host(s) scanned on " + network + ", " + str(
            hostsUp) + " host(s) up, " + str(
            blockedHosts) + " host(s) blocking ICMP")


def ArpRequest(ip, timeout):
    target = ip
    target_ip = target.split('/')
    target_ip_bytes = target_ip[0].split('.')
    if target_ip_bytes[3] == '0':
        print("[*] (A single target ending by a 0 may not respond)")
    arp_r = ARP(pdst=target_ip)
    br = Ether(dst='ff:ff:ff:ff:ff:ff')
    request = br / arp_r
    answered, unanswered = srp(request, timeout=timeout, verbose=0)
    for i in answered:
        print("[*] " + i[1].psrc + " responded: " + i[1].hwsrc.upper())
    if str(len(answered)) == '1':
        print("[+] ARP Request End, " + str(len(answered)) + " response(s) received from " + str(target_ip[0]))
    else:
        print("[x] ARP Request End, no response(s) received from " + str(target_ip[0]))


def ArpScan(network, timeout):
    try:
        addresses = IPv4Network(network)
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
    except KeyboardInterrupt:
        print("[+] ARP Request stopped, " + str(len(answered)) + " response(s) received from " + str(network))


# Definition of the function get portsScan()
def TCPportsScan(startingPort, endingPort, ip):
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


def fastTcpPortsScan(portList, ip):
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


try:
    if len(sys.argv) < 2:
        exit(
            "[x] No parameter(s) selected, use protocol scan available: ('-TCP', '-ARP', '-ICMP'), or use option: '-h' ")
    else:
        if sys.argv[1] == '-h':
            print(
                "\n(If the script output: 'WARNING: Mac address to reach destination not found. Using broadcast.' use ARP Scan instead of ICMP Scan or put the mask on a single target)")
            print("(If you find any problems,errors or bugs please contact me at 'https://github.com/DrDJ3006')")
            print("\n[*] Help")
            print(" ICMP Scan:")
            print("   - Input '-ICMP'")
            print("   - Select a network to scan with '-n', (Ex: '... -ICMP -n 192.168.2.0/24')")
            print("     (if you want to scan your local network use ARP Scan instead it's faster =D )")
            print(" ARP Scan:")
            print("   - Input '-ARP'")
            print("   - Select a network to scan with '-n', Ex: ('... -ARP -n 192.168.1.0/24')")
            print("   - Select a single target to request with '-t', Ex: ('... -ARP -t 192.168.1.254/24')")
            print(" TCP (Ports) Scan:")
            print("   - Input '-TCP'")
            print(
                "   - Select a target to scan with '-t', Ex: ('... -TCP -t 192.168.1.254/24') (default port scan 1 to 1024) ")
            print(
                "   - Select the fast scan with '-f', Ex: ('... -TCP -t 192.168.1.254/24 -f') (This option scan all ports referenced in the 'port_protocol_tcp' list in which you can add known ports to them if you wish)")
            print("   - Select the port range to scan with '-r', Ex: ('... -TCP -t 192.168.1.254/24 -r 1-65535')")
            print("   - Select a single port to scan with '-p', Ex: ('... -TCP -t 192.168.1.254/24 -p 22')")
            print(" UDP (Ports) Scan:")
            print("   - Input '-UDP' (not available for the moment)")
            exit()
        elif sys.argv[1] == '-ICMP':
            try:
                if sys.argv[2] == '-n':
                    try:
                        target_network = sys.argv[3]
                        if ip_address(self_ip) in ip_network(target_network, strict=False):
                            exit("[x] For scan you local Network use the ARP Scan instead")
                        else:
                            target_network_ip, target_network_mask = target_network.split('/', maxsplit=1)
                            pingScan(target_network, timeout_icmp)
                    except ValueError:
                        exit("[x] Invalid IP network: '" + target_network + "', look at the network ip and the mask (network ip often end by a 0)")
                    except IndexError:
                        exit("[x] No ICMP network selected, please input a network to scan after '-n', Ex: ('... -ICMP -n 192.168.2.0/24')")
                else:
                    exit("[x] Unknown parameter(s) '" + str(
                        sys.argv[2]) + "', use ('-n') for input a network, Ex: ('... -ICMP -n 192.168.2.0/24')")
            except IndexError:
                exit("[x] No ICMP parameter(s) selected, please input a network to scan with ('-n')")
        elif sys.argv[1] == '-ARP':
            try:
                if sys.argv[2] == '-n':
                    try:
                        target_network = sys.argv[3]
                        addresses = IPv4Network(target_network)
                        target_network_ip, target_network_mask = target_network.split('/', maxsplit=1)
                        if target_network_mask:
                            if ip_address(self_ip) in ip_network(target_network, strict=False):
                                getHead('ARP', target_network, 1, 1, timeout_arp, True, 'network')
                                ArpScan(target_network, timeout_arp)
                            else:
                                exit("[x] ARP Scan is only available on your local network, use ICMP scan instead")
                    except IndexError:
                        exit("[x] No ARP network selected, please input a network to scan after '-n', Ex: ('... -ARP -n 192.168.1.0/24')")
                    except AddressValueError:
                        exit("[x] Invalid IP network: '" + target_network + "', please look at the ip format or the mask (the mask is mandatory for the ARP Scan) ")
                    except ValueError:
                        exit("[x] Invalid IP network: '" + target_network + "', please look if the ip is corresponding to the mask (the mask is mandatory for the ARP Scan, ip network often end by a 0)")
                elif sys.argv[2] == '-t':
                    try:
                        target_ip = sys.argv[3]
                        target_ipv4, target_mask = target_ip.split('/', maxsplit=1)
                        if target_mask:
                            if ip_address(self_ip) in ip_network(target_ip, strict=False):
                                getHead('ARP', target_ip, 1, 1, timeout_arp, True, 'target')
                                ArpRequest(target_ip, timeout_arp)
                            else:
                                exit("[x] ARP request is only available on you local network")
                    except ValueError:
                        exit("[x] Invalid IP target: '" + target_ip + "', please look at the ip format or the mask (the mask is mandatory for the ARP Scan) ")
                    except IndexError:
                        exit("[x] No ARP target selected, please input a target to request after '-t', Ex: ('... -ARP -t 192.168.1.1/24')")
                else:
                    exit("[x] Unknown parameter(s) '" + str(sys.argv[2]) + "', use ('-n') for input a network, or input a target with: ('-t'), Ex : ('... -n 192.168.1.0/24') or ('... -t 192.168.1.254/24')")
            except IndexError:
                exit(
                    "[x] No ARP parameter(s) selected, please input a network to scan with: ('-n'), or input a target to request with ('-t')")
        elif sys.argv[1] == '-TCP':
            try:
                if sys.argv[2] == '-t':
                    target_ip = sys.argv[3]
                    target_ip_split = target_ip.split('/', maxsplit=1)
                    try:
                        if target_ip_split[1]:
                            if ip_address(self_ip) not in ip_network(target_ip, strict=False):
                                exit("[x] Please don't enter the mask if the target ip is not in your local network")
                    except IndexError:
                        try:
                            if ip_address(self_ip) in ip_network(target_ip, strict=False):
                                getHead('ARP', target_ip, 1, 1, timeout_arp, True, 'target')
                                ArpRequest(target_ip, timeout_arp)
                        except ValueError:
                            exit("[x] Invalid IP target: '" + target_ip + "', please look at the ip format or the mask")
                    except ValueError:
                        exit("[x] Invalid IP target: '" + target_ip + "', please look at the ip format or the mask")
                    try:
                        if sys.argv[4] == '-r':
                            try:
                                ports = sys.argv[5].split('-', maxsplit=1)
                                firstPort = int(ports[0])
                                lastPort = int(ports[1])
                                if int(firstPort) > 65535 or int(firstPort) < 1:
                                    exit("[x] Invalid fist port of range : '" + str(firstPort) + "', use a number between 1 and 65535")
                                elif int(lastPort) > 65535 or int(lastPort) < 1:
                                    exit("[x] Invalid last port of range: '" + str(lastPort) + "', use a number between 1 and 65535")
                            except IndexError:
                                exit("[x] Please input a port range after '-r', with this format: ('... -t 192.168.1.1 -r 1-65535') (Scanning port 1 to port 65535)")
                            except ValueError:
                                exit("[x] Invalid port range: '" + sys.argv[
                                    5] + "', use this format: (' ... -r {1-655535}-{1-655535} ')")
                        elif sys.argv[4] == '-p':
                            try:
                                if int(sys.argv[5]) > 65535 or int(sys.argv[5]) < 1:
                                    exit("[x] Invalid port number: '" + sys.argv[
                                        5] + "', use a number between 1 and 65535")
                                firstPort = int(sys.argv[5])
                                lastPort = int(sys.argv[5])
                            except IndexError:
                                exit(
                                    "[x] Please input a port range after '-p', with this format: ('... -t 192.168.1.1 -p 80 ') (Scanning only the port 80)")
                            except ValueError:
                                exit("[x] Invalid Port: '" + sys.argv[5] + "', use a number between 1 and 65535")
                        elif sys.argv[4] == '-f':
                            target_ip = getPing(target_ip)
                            getHead('TCP', target_ip, 1, len(port_protocol_tcp), timeout_tcp, True, 'target')
                            fastTcpPortsScan(port_protocol_tcp, target_ip)
                            exit()
                        else:
                            exit("[x] Unknown parameter(s) '" + str(sys.argv[4]) + "' use '-p' for scan a single port or '-r' for select a range of ports or '-f' for select the fast scan")
                    except IndexError:
                        firstPort = 1
                        lastPort = 1024
                    target_ip = getPing(target_ip)
                    getHead('TCP', target_ip, firstPort, lastPort, timeout_tcp, False, 'target')
                    TCPportsScan(firstPort, lastPort, target_ip)
                else:
                    exit("[x] Unknown parameter(s) '" + str(sys.argv[2]) + "', use ('-t') for input a target , Ex: ('... -TCP -t 192.168.1.1/24')")
            except IndexError:
                exit("[x] No TCP parameter(s) selected, please input a target to scan with ('-t')")
        elif sys.argv[1] == '-UDP':
            exit("[*] UDP scan not available for the moment sry =D")
        else:
            exit("[x] Unknown parameter(s) '" + str(sys.argv[1]) + "', protocol scan available: ('-TCP', '-ARP', '-ICMP')")
except PermissionError:
    exit("[x] Please run the script as root")
except socket.gaierror:
    exit("[x] Ip target(s) or network invalid")
except OSError:
    exit("[x] Ip target(s) or network invalid")