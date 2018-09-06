# Mr.SIP
SIP-Based Audit and Attack Tool

Mr.SIP is a tool developed to audit and simulate SIP-based attacks. Originally it was developed to be used in academic work to help developing novel SIP-based DDoS attacks and then as an idea to convert it to a fully functional SIP-based penetration testing tool.

It has been used in an academic journal paper titled "Novel SIP-based DDoS Attacks and Effective Defense Strategies" published in Computers & Security 63 (2016) 29-44 by Elsevier, Science Direct http://sciencedirect.com/science/article/pii/S0167404816300980.


In the current state, Mr.SIP comprises four sub-modules named as SIP-NES, SIP-ENUM, SIP-DAS and SIP-ASP. Since it provides a modular structure to developers, more modules will continue be added by the authors and it is open to be contributed by the open-source developer community.


SIP-NES needs to enter the IP range or IP subnet information. It sends SIP OPTIONS message to each IP addresses in the subnet and according to the responses outputs the potential SIP clients and servers on that subnet.


SIP-ENUM outputs which SIP users are valid according to the responses in that network by sending REGISTER messages to each client IP addresses on the output of SIP-NES.


SIP-DAS (DoS Attack Simulator) is a module developed to simulate SIP-based DoS attacks. It comprises four components: spoofed IP address generator, SIP message generator, message sender and scenario player. It needs outputs of SIP-NES (Network Scanner) and SIP-ENUM (Enumerator) along with some pre-defined files.


SIP-DAS basically generates legitimate SIP INVITE message and sends it to the target SIP component via TCP or UDP. It has three different options for spoofed IP address generation, i.e., manual, random and by selecting spoofed IP address from subnet. IP addresses could be specified manually or generated randomly. Furthermore, in order to bypass URPF filtering, which is used to block IP addresses that do not belong to the subnet from passing onto the Internet, we designed a spoofed IP address generation module. Spoofed IP generation module calculated the subnet used and randomly generated spoofed IP addresses that appeared to come from within the subnet.


In order to bypass automatic message generation detection (anomaly detection) systems, random “INVITE” messages are generated that contained no patterns within the messages. Each generated “INVITE” message is grammatically compatible with SIP RFCs and acceptable to all of the SIP components.


“INVITE” message production mechanism specifies the target user(s) in the “To” header of the message. This attack can be executed against a single user or against legitimate SIP users on the target SIP server as an intermediary step before the DoS attack. The legitimate SIP users are enumerated and written to a file. Next, they are placed randomly in the “To” header of the generated “INVITE” messages. “Via, “User-Agent, “From,” and “Contact” headers within an “INVITE” message were syntactically generated using randomly selected information from the valid user agent and IP address lists. The tag parameter in the “From” header, the branch and source-port parameters in the “Via” header, and the values in the “Call-ID” header are syntactically and randomly generated using the valid user agent list. In addition, the source IP addresses in the “Contact” and “Via” headers are also generated using IP spoofing.


UDP is used widely in SIP systems as a transport protocol, so attacks on the target server are implemented by sending the generated attack messages in the network using UDP. Also TCP can be used optionally. The message sender of SIP-DAS allows the optional selection of how many SIP messages could be sent during one second. The number of SIP messages sent in one second depended on the resources (CPU and RAM) of the attacker machine.


SIP-ASP (Attack Scenario Player) allows the development of various SIP-based DoS attack scenarios through the use of SIP-DAS as the framework.

Usages Examples: 

SIP-NES scan output

![Alt text](/screenshots/SIP-NES-scan.jpg?raw=true "SIP-NES scan output")

Call flow created by SIP-NES

![Alt text](/screenshots/SIP-NES-messages.jpg?raw=true "Call flow created by SIP-NES")

SIP-DAS attack output

![Alt text](/screenshots/SIP-DAS-attack.jpg?raw=true "SIP-DAS attack output")

Call flow created by SIP-DAS

![Alt text](/screenshots/SIP-DAS-messages.jpg?raw=true "Call flow created by SIP-DAS")





