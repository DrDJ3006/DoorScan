

# DoorScan :

DoorScan is a simple Scan Script using python3 and the scapy library
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
###ICMP Scan:
```
(not available for the moment)
``` 
###ARP Scan:
- Select a network to scan with '-n' 
``` 
python3 DoorScan.py -ARP -n 192.168.1.0/24
``` 
- Select a single target to request with '-t'
``` 
python3 DoorScan.py -ARP -t 192.168.1.254
``` 
###TCP (Ports) Scan:
- Select a target to scan with '-t' 
``` 
python3 DoorScan.py -TCP -t 192.168.1.254 (default port scan 1 to 1024) 
``` 
- Select the port range to scan with '-r'
``` 
python3 DoorScan.py -TCP -t 192.168.1.254 -r 1-65535
``` 
- Select a single port to scan with '-p'
``` 
python3 DoorScan.py -TCP -t 192.168.1.254 -p 22
``` 
# Bugs and problems : 
Please if you find a problem, or a bug let me know =D.
# legal disclaimer:
Usage of DoorScan for attacking targets without prior mutual consent is illegal. 
It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. 
Only use for educational purposes.
