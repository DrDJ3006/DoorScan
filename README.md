

# DoorScan :

DoorScan is a simple scan script using python3 and scapy library
# Installation & dependencies :
## Dependencies :
- Python 3.5+
- Scapy 2.4.5+

## Installation :
- Clone the github repo : 
```
git clone https://github.com/DrDJ3006/DoorScan.git
```
- Install all libraries with requirements.txt : 
```
pip3 install -r requirements.txt
```
# Use :
The script must be run as root
```
python3 DoorScan.py
```
### ICMP Scan:
- Select a network to scan with '-n' 
``` 
python3 DoorScan.py -ICMP -n 192.168.1.0/24
```
(if you want to scan your local network use ARP Scan instead it's faster =D )
### ARP Scan:
- Select a network to scan with '-n' 
``` 
python3 DoorScan.py -ARP -n 192.168.1.0/24
``` 
- Select a single target to request with '-t'
``` 
python3 DoorScan.py -ARP -t 192.168.1.254
``` 
### TCP (Ports) Scan:
if you scan a target in your local network input a mask with the IP address 
- Select a target to scan with '-t' 
``` 
python3 DoorScan.py -TCP -t 192.168.1.254/24 (default port scan 1 to 1024) 
``` 
- Select the port range to scan with '-r'
``` 
python3 DoorScan.py -TCP -t 192.168.1.254/24 -r 1-65535
``` 
- Select a single port to scan with '-p'
``` 
python3 DoorScan.py -TCP -t 192.168.1.254/24 -p 22
``` 
- Select the fast scan with '-f'
``` 
python3 DoorScan.py -TCP -t 192.168.1.254/24 -f
```
(This option scan all ports referenced in the 'port_protocol_tcp' list in which you can add known ports to them if you wish)
# Bugs and problems : 
Please if you find a problem, or a bug let me know =D.
# legal disclaimer:
Usage of DoorScan for attacking targets without prior mutual consent is illegal. 
It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. 
Only use for educational purposes.
