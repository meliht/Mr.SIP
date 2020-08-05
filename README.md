[![Black Hat Arsenal](https://github.com/meliht/Mr.SIP/blob/master/BlackHatArsenalEU2019bagdge.svg)](https://www.blackhat.com/eu-19/arsenal/schedule/#mrsip-sip-based-audit--attack-tool-18190)
[![Black Hat Arsenal](https://github.com/meliht/Mr.SIP/blob/master/BlackHatArsenalUSA2019bagdge.svg)](https://www.blackhat.com/us-19/arsenal/schedule/index.html#mrsip-sip-based-audit--attack-tool-16866)
[![Black Hat Arsenal](https://github.com/meliht/Mr.SIP/blob/master/BlackHatArsenalAsia2019bagdge.svg)](https://www.blackhat.com/asia-19/arsenal/schedule/index.html#mrsip-sip-based-audit-and-attack-tool-14381)
[![Offzone Moscow](https://github.com/meliht/Mr.SIP/blob/master/OffzoneMoscow2019badge.svg)](https://offzone.moscow/report/mr-sip-sip-based-audit-and-attack-tool/)

_________________________________________
# < Mr.SIP: SIP-Based Audit and Attack Tool! >
 -------------------------------------------
 
 ## What is Mr.SIP (public version)?

Mr.SIP is a simple console based SIP-based Audit and Attack Tool. Originally it was developed to be used in academic work to help developing novel SIP-based DDoS attacks and then as an idea to convert it to a fully functional SIP-based penetration testing tool. So far Mr SIP resulted several academic research papers, and journal articles. Mr.SIP can also be used as SIP client simulator and SIP traffic generator.

In the current state, public version of Mr.SIP contains 3 modules; SIP-NES (network scanner), SIP-ENUM (enumerator), SIP-DAS (DoS attack simulator). It detects SIP components and existing users on the network and generate various TDoS attacks. Mr.SIP has some competitive features including; high performance multi-threading, powerful IP spoofing engine and  smart SIP message generation. We have seen practitioners also use Mr.SIP as a client simulator and traffic generator.

## Mr.SIP Public Version Modules
* Network Scanner detects SIP components, manufacturer and version information. 
* SIP Enumerator identifies valid SIP users and authentications information. 
* You can performs TDoS-based attacks using DoS Attack Simulator which has a powerful IP spoofer.

## What is Mr.SIP Pro (private version)? 
Mr.SIP Pro is the most comprehensive attack oriented VoIP product ever! In the Pro version, we have added 7 more modules. We also extended the public modules with new features. In Pro version, it contains 10 modules in 3 categories; Information Gathering, Vulnerability Scanning and Offensive Modules. There are 2 helper components called: IP Spoofing Engine and Message Generator. Also in our roadmap; there are 5 new attack modules. In addition, we will develop an easy-to-use GUI. 

Mr.SIP is a tool that should be in every pentester's and red teamer's toolbox. It detects SIP components and existing users on the network, intervenes and filters and manipulates call information, reports known vulnerabilities and exploits, develops various TDoS attacks, including status-controlled advanced ones and breaks user passwords. It also has many innovative and competitive features. For example; high performance multi-threading, IP spoofing, smart SIP message generation, self-hiding and intervention skills. Mr.SIP has also customisable scenario development framework for stateful attacks. 

**Information Gathering Modules:**
* SIP-NES (network scanner)
* SIP-ENUM (SIP enumerator)
* SIP-SNIFF (SIP traffic sniffer)
* SIP-EAVES (call eavesdropper)

**Vulnerability Scanning:**
* SIP-VSCAN (vulns & exploit scanner)

**Offensive Modules:**
* SIP-DAS (DoS attack simulator)
* SIP-MANMID (MiTM attacker)
* SIP-ASP (attack scenario player)
* SIP-CRACK (digest authentication cracker)
* SIP-SIM (signaling manipulator)

## Mr.SIP Pro 10 Modules (more to come)
* Network Scanner detects SIP components, manufacturer and version information. 
* SIP Enumerator identifies valid SIP users and authentications information. 
* You can capture SIP traffic using SIP Sniffer which also supports MiTM attack. 
* Eavesdropper allows you listen the SIP traffic and collect the call-specific information and it supports MiTM attack too.
* SIP-VSCAN detects and reports known vulnerabilities and exploits. 
* You can performs TDoS-based attacks, ush DoS Attack Simulator which has a powerful IP spoofer.
* We have seperated MiTM Attacker which allows to act as a proxy in the network.
* Attack Scenario Player allows to perform stateful SIP scenarios, and it has pre-defined attack scenarios, you can also add more. 
* By using SIP Password Cracker you can performs real-time digest authentication cracking by intervening which also support MiTM attack too.
* Signaling Manipulator allows generating custom SIP messages helping to perform caller-id spoofing attacks.

## Roadmap of Mr.SIP Pro: 
We will add 5 new modules along with a friendly GUI. We will add fuzzing, media sniffing, media injection/manipulation, robocall (SPIT) and DTMF tone stealing features soon. 

## How to Support Mr.SIP 
Please give star in our Github, please follow our empty Twitter account for updates. And, please subscribe our Youtube channel as we need 100 subscribers to update the URL.

* Website: (https://mrsip.pro/)
* Gitlab: (https://mrsip.gitlab.io)
* Twitter: (https://twitter.com/mrsip_official)
* Youtube: (https://www.youtube.com/channel/UCgrI4qYdhrlPjxG8OtxqSkw)

If you want you get more out of Mr.SIP, check out PRO version ---> https://mrsip.gitlab.io/

## Mr.SIP Pro Installation
Mr.SIP is a console based Python tool. In order to run Mr.SIP in your Kali, you need install some python libraries. Please see help and usage for full instructions. 

```
pip install -r requirements.txt
apt-get install python-scapy
```
```
python mr.sip.py --help
python mr.sip.py –usage
```

##  Mr.SIP Usages: 

**General Usage:** 
```
python mr.sip.py [--nes|--enum|--das| --sniff| --manmid| --eaves| --crack| --sim| --asp| --vscan] [parameters]
```

**Global Default Parameters If Not Given:** \
Default interface (--if=)  is eth0 \
Default thread count (--tc=) is 10 \
Default destination port (--dp=) is 5060 

**SIP-NES Usage:** 
```
python mr.sip.py --nes --tn=<target_IP> --mt=options --from=<from_extention> --to=<to_extension>
python mr.sip.py --nes --tn=<target_network_range> --mt=invite --from=<from_extention> --to=<to_extension>
python mr.sip.py --nes --tn <target_network_address> --mt=subscribe --from=<from_extention> --to=<to_extension>
```

NOTE-1: _<target_network_range>_ should be like `192.168.1.10-192.168.1.20` \
NOTE-2: _<target_network>_ should be like `192.168.1.0` \
NOTE-3: You can specify the output by `-i <output_file_name>`. By default the output will be written to _ip_list.txt_ file which is already exists in the repo. _SIP-ENUM_ uses that file as an input. \
NOTE-4: Default destination (--dp) is _port 5060_, if not given. \
NOTE-5: Default message type (--mt=) is _options_, if not given. \
NOTE-6: Supported message types: _options_, _invite_, _subscribe_, _register_ \
NOTE-7: _from_ and _to_ values can be arbitrary extension number.

**Output of SIP-NES:** 

![Alt text](/screenshots/SIP-NES-scan.png?raw=true "SIP-NES scan output")

**SIP-ENUM Usage:** 
```
python mr.sip.py --enum --from=from.txt 
python mr.sip.py --enum --tn=<target_IP> --from=from.txt
```

NOTE-1: If target network (--tn) is not given, SIP-ENUM uses _ip_list.txt_ file as an input which is output of SIP-NES. \
NOTE-2: Default from user (--from=) is _fromUser.txt_ \
NOTE-3: Default message type (--mt) is _subscribe_, if not given.

**Output of SIP-ENUM:** 

![Alt text](/screenshots/SIP-ENUM-scan.png?raw=true "SIP-ENUM scan output")


**SIP-DAS Usage:** \
By using scapy library (IP spoofing is supported) 
```
python mr.sip.py --das -mt=invite -c <package_count> --tn=<target_IP> -r 
python mr.sip.py --das --mt=invite -c <package_count> --tn=<target_IP> -s 
python mr.sip.py --das --mt=invite -c <package_count> --tn=<target_IP> -m --il=ip_list.txt
```

By using socket library (but doesn't support IP spoofing)
```
python mr.sip.py --das -mt=invite -c <package_count> --tn=<target_IP> -r -l
python mr.sip.py --das --mt=invite -c <package_count> --tn=<target_IP> -s -l 
python mr.sip.py --das --mt=invite -c <package_count> --tn=<target_IP> -m --il=ip_list.txt -l
```

NOTE-1: Default to users (--to=) is _toUser.txt_ \
NOTE-2: Default from users (--from=) is _fromUser.txt_ \
NOTE-3: Default user-agent (--ua=) is _userAgent.txt_ \
NOTE-4: Default packet counter (-c=) is flood

**Output of SIP-DAS:** 

![Alt text](/screenshots/SIP-DAS-attack.png?raw=true "SIP-DAS attack output")

## Media Mentions and Citations
* Mr.SIP is evolving and actively being used by researchers and practitioners.
* Shared on various popular forums and news sources, including BlackHat's homepage. [Here](https://www.blackhat.com/latestintel/01222019-discover-new-tools.html)
* Cited in Cisco publications.
* Used in Caller-ID spoofing tests as part of Turkish Standards Institute (TSE) collaboration for national VoIP standard setting studies.
* Used in various prestigious academic publications. (Elsevier, IEEE)

## References
* I. M. Tas, B.G.Unsalver, and S. Baktir, "A Novel SIP Based Distributed Reflection Denial-of-Service Attack and an Effective Defense Mechanism",
IEEE Access 2020-25937, Vol. 8, pp. 112574–112584, June. 2020 [Read More](https://ieeexplore.ieee.org/abstract/document/9114982)
* I. M. Tas, B. Ugurdogan, and S. Baktir, ‘‘Novel Session Initiation Protocol Based Distributed Denial-of-Service Attacks and Effective Defense
Strategies,’’ Computers & Security, Vol. 63, pp. 29–44, Nov. 2016 [Read More](https://www.sciencedirect.com/science/article/pii/S0167404816300980)
* [Defcon28 2020](https://www.defcon.org/html/defcon-safemode/dc-safemode-speakers.html#Tas)
* [BlackHat EU 2019](https://www.blackhat.com/eu-19/arsenal/schedule/index.html#mrsip-sip-based-audit--attack-tool-18190)
* [BlackHat USA 2019](https://www.blackhat.com/us-19/arsenal/schedule/#mrsip-sip-based-audit--attack-tool-16866)
* [Offzone Moscow 2019](https://www.offzone.moscow/report/mr-sip-sip-based-audit-and-attack-tool/)
* [BlackHat Asia 2019](https://www.blackhat.com/asia-19/arsenal/schedule/index.html#mrsip-sip-based-audit-and-attack-tool-14381)
