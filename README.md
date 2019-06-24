[![Black Hat Arsenal](https://github.com/meliht/Mr.SIP/blob/master/BlackHatArsenalAsia2019bagdge.svg)](https://www.blackhat.com/asia-19/arsenal/schedule/index.html#mrsip-sip-based-audit-and-attack-tool-14381)
[![Offzone Moscow](https://github.com/meliht/Mr.SIP/blob/master/OffzoneMoscow2019badge.svg)](https://offzone.moscow/report/mr-sip-sip-based-audit-and-attack-tool/)

_________________________________________
< Mr.SIP: SIP-Based Audit and Attack Tool! >
 -------------------------------------------

Mr.SIP is a simple console based SIP-based Audit and Attack Tool. Originally it was developed to be used in academic work to help developing novel SIP-based DDoS attacks and then as an idea to convert it to a fully functional SIP-based penetration testing tool.

Initially it was developed to be used in academic researches to help developing novel SIP-based DDoS attacks and then as an idea to convert it to a fully functional SIP-based penetration testing tool. So far it has been used more than 5 journal papers. Mr.SIP can also be used as SIP client simulator and SIP traffic generator.

The initial academic journal paper which Mr.SIP is used is titled "Novel SIP-based DDoS Attacks and Effective Defense Strategies" published in Computers & Security 63 (2016) 29-44 by Elsevier, Science Direct http://sciencedirect.com/science/article/pii/S0167404816300980.

In the current state, Mr.SIP comprises 3 sub-modules named as SIP-NES (network scanner), SIP-ENUM (enumerator), SIP-DAS (DoS attack simulator). Also 4 new modules will be adding very soon namely SIP-ASP (attack scenario player), SIP-EVA (eavesdropper), SIP-SIM (signaling manipulator) and SIP-CRACK (cracker). Since it provides a modular structure to developers, more modules will continue be added by the authors and it is open to be contributed by the open-source developer community.
 
SIP-NES is a network scanner. It needs the IP range or IP subnet information as input. It sends SIP OPTIONS message to each IP addresses in the subnet/range and according to the responses, it provides the output of the potential SIP clients and servers on that subnet.

SIP-ENUM is a enumerator. It needs the output of SIP-NES and also pre-defined SIP usernames. It generates SIP REGISTER messages and sends them to all SIP components and try to find the valid SIP users on the target network. You can write the output in a file.

SIP-DAS is a DoS/DDoS attack simulator. It comprises four components: powerful spoofed IP address generator, SIP message generator, message sender and response parser. It needs the outputs of SIP-NES and SIP-ENUM along with some pre-defined files.
 
IP spoofing generator has 3 different options for spoofed IP address generation, i.e., manual, random and by selecting spoofed IP address from subnet. IP addresses could be specified manually or generated randomly. Furthermore, in order to bypass URPF filtering, which is used to block IP addresses that do not belong to the subnet from passing onto the Internet, we designed a spoofed IP address generation module. Spoofed IP generation module calculated the subnet used and randomly generated spoofed IP addresses that appeared to come from within the subnet.

SIP-DAS basically generates legitimate SIP INVITE message and sends it to the target SIP component via TCP or UDP. In the current state it doesn't support instrumentation which helps you to understand the impact of the attack by using Mr.SIP, but we will support it very soon. In the current state, we can see the impact of the attack by checking the CPU and memory usage of the victim SIP server.

SIP is a text based protocol such as HTTP but more complex than HTTP. For example, when we talk about SIP INVITE message, there are some specific headers and parameters need to be vendor specific and unique for each call. SIP Message Generator allows you to bypass security perimeters bu generating all these headers and parameters as it should be, so basic it is harder to be detected by anomaly detection engines that these messages are generated automatically. You can generate SIP methods such as INVITE message, REGISTER message etc. 

You can specify the message count, the destination port, you can use predefined toUser list, fromUser list, userAgent list etc.
 
In order to bypass automatic message generation detection (anomaly detection) systems, random "INVITE" messages are generated that contained no patterns within the messages. Each generated "INVITE" message is grammatically compatible with SIP RFCs and acceptable to all of the SIP components.
 
"INVITE" message production mechanism specifies the target user(s) in the "To" header of the message. This attack can be executed against a single user or against legitimate SIP users on the target SIP server as an intermediary step before the DoS attack. The legitimate SIP users are enumerated and written to a file. Next, they are placed randomly in the "To" header of the generated "INVITE" messages. "Via, "User-Agent, "From," and "Contact" headers within an "INVITE" message were syntactically generated using randomly selected information from the valid user agent and IP address lists. The tag parameter in the "From" header, the branch and source-port parameters in the "Via" header, and the values in the "Call-ID" header are syntactically and randomly generated using the valid user agent list. In addition, the source IP addresses in the "Contact" and "Via" headers are also generated using IP spoofing.
 
UDP is used widely in SIP systems as a transport protocol, so attacks on the target server are implemented by sending the generated attack messages in the network using UDP. Also TCP can be used optionally. The message sender of SIP-DAS allows the optional selection of how many SIP messages could be sent during one second. The number of SIP messages sent in one second depended on the resources (CPU and RAM) of the attacker machine.
 
SIP-ASP is Attack Scenario Player. It is working like a sub function of SIP-DAS. It has a powerful parser and allows you to create stateful SIP attack call flows. In our academic studies, we have developed new attack vectors by using our SIP-DAS and SIP-ASP such as re-transmission based DDoS attacks and reflection based DRDoS attacks. 

SIP-EVA is an eavesdropper. It sniffs the target network and can grasp the SIP messages. It allows you to extract call specific information such as who is calling, who i called, the duration of the call, the unique call-ID value and you can even download the media content of the call.

SIP-SIM is a signaling manipulator. It is working like Intercepting SIP Proxy. It uses the same sniffer mechanism with SIP-EVA but it allows you to catch the messages between clients and server and you can replicate the messages and manipulate some headers and/or parameters as you want and send it to the victim server.  

By using SIP-SIM you can do do Caller-ID spoofing attacks. SIP-SIM support both LAN-based and WAN-based Caller-ID spoofing attacks. But in order to make WAN-based Caller-ID spoofing attack, you need to have proper service provider account. 

SIP-CRACK is a password cracker. Again, it uses the same sniffing mechanism and it allows you to catch the SIP REGISTER messages, extract the authentication data such as hash values. You can do brute-force based cracking, or you can choose dictionary or rainbow table cracking. So SIP is a time critical protocol and cracking should be an offline attack. 

# Installation

Install using pip:

pip install netifaces
pip install ipaddress
pip install pyfiglet 

Install using apt:

apt-get install python-scapy


# Usages Examples: 

SIP-NES usage:

./mr.sip.py --ns --tn <target_ip> --dp=5060  
./mr.sip.py --ns --tn <target_network_range> --dp=5060
./mr.sip.py --ns --tn <target_network_address> --dp=5060 

NOT-1: <target_network_range> should be like 192.168.1.10-192.168.1.20
NOT-2: <target_network> should be like 192.168.1.0
NOT-3: You can specify the output by -i <output_file_name>. By default the output will be written to ip_list.txt file which is already exists in the repo. SIP-ENUM uses that file as an input. 
NOT-3: Default destionation port 5060, if not given. 

Scan output: 

![Alt text](/screenshots/SIP-NES-scan.png?raw=true "SIP-NES scan output")

Call flow created by SIP-NES on the target SIP server:

sudo ngrep -W byline -d eth0 port 5060 

![Alt text](/screenshots/SIP-NES-messages.png?raw=true "Call flow created by SIP-NES")

SIP-ENUM usage:

./mr.sip.py --se --dp=5060 --fu=fromUser.txt

NOT-1: SIP-ENUM uses ip_list.txt file as an input. 

Scan output: 

![Alt text](/screenshots/SIP-ENUM-scan.png?raw=true "SIP-ENUM scan output")

Call flow created by SIP-NES on the target SIP server:

sudo ngrep -W byline -d eth0 port 5060 

![Alt text](/screenshots/SIP-ENUM-messages.png?raw=true "Call flow created by SIP-ENUM")

SIP-DAS usage:

by using socket library (but doesn't support IP spoofing) \

./mr.sip.py --ds -dm=<sip_method_name> -c <number_of_packets> --di=<target_IP_address> --dp=5060 -r --to=toUser.txt --fu=fromUser.txt --ua=userAgent.txt --su=spUser.txt -l

by using scapy library (ip spoofing is supported) 

./mr.sip.py --ds -dm=invite -c <number_of_packets> --di=<target_IP_address> --dp=<server_port> -r --to=toUser.txt --fu=fromUser.txt --ua=userAgent.txt --su=spUser.txt 

./mr.sip.py --ds -dm=invite -c <number_of_packets> --di=<target_IP_address> --dp=<server_port> -s --to=toUser.txt --fu=fromUser.txt --ua=userAgent.txt --su=spUser.txt 

./mr.sip.py --ds -dm=invite -c <number_of_packets> --di=<target_IP_address> --dp=<server_port> -m --to=toUser.txt --fu=fromUser.txt --ua=userAgent.txt --su=spUser.txt --il=ip_list.txt 

Attack output:

![Alt text](/screenshots/SIP-DAS-attack.png?raw=true "SIP-DAS attack output")

Call flow created by SIP-DAS on the target SIP server: 

sudo ngrep -W byline -d eth0 port 5060 

![Alt text](/screenshots/SIP-DAS-messages.png?raw=true "Call flow created by SIP-DAS")





