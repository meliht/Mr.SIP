"""
#####################################################################################################
        ################################   Importing Packages  ################################ 
#####################################################################################################
"""

import ipaddress, random, os, argparse
import socket, struct

"""
#####################################################################################################
        ################################   Utility Code  ################################ 
#####################################################################################################
"""

def readFile(file):
    f = open(file, "r")
    content = f.read()
    f.close()
    return content


def writeFile(file, content):
    f = open(file, "a+")
    f.write(content)
    f.close()

def randomIPAddressFromNetwork(IP, Netmask, Network):
    network = ""
    if Network:
        network = Network
    else:
        network = "{0}/{1}".format(str(IP), str(Netmask))
    # print('variable: {}, str(variable): {}'.format(network, str(network)))
    targetNetwork = ipaddress.IPv4Network(str(network), strict=False)
    ipCount = int(targetNetwork.num_addresses)
    firstIpAddress = targetNetwork.network_address
    randomInt = random.randint(0, ipCount - 1)
    randomIpAddress = (firstIpAddress + randomInt)
    return str(randomIpAddress.exploded)


def randomIPAddress():
    return ".".join([str(random.randrange(1, 255)), str(random.randrange(1, 255)), str(random.randrange(1, 255)),
                     str(random.randrange(1, 255))])


def promisc(state, iface):
    # Manage interface promiscuity. valid states are on or off
    ret = os.system("ip link set {0} promisc {1}".format(iface, state))
    if ret == 1:
        print("You must run this script with root permissions.")


def printProgressBar(iteration, total, prefix='', decimals=1, length=100, fill='|'):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print('%s |%s| %s%%\r' % (prefix, bar, percent), end=' ')
    if iteration == total:
        print('')


def defineTargetType(user_agent):
    serverList = [server.upper() for server in readFile('servers.txt').split("\n") if server.isalnum()]
    for server in serverList:
        if server in user_agent.upper(): return "Server"
    else: return "Client"


# Print functions:
def printInital(moduleName, client_iface, client_ip):
    print(("\033[33m[!] Client Interface: {}\033[0m".format(str(client_iface))))
    print(("\033[33m[!] Client IP: {}\033[0m".format(str(client_ip))))
    print(("\033[94m[!] {} process started. \033[0m".format(moduleName)))


def printResult(result, target, ops_ip_list):
    if '.' not in target: target = socket.inet_ntoa(struct.pack('!L', int(target)))
    user_agent = ""
    for key, value in list(result["response"]['headers'].items()):
        if key == "user-agent":
            user_agent = list(value)[0]
        elif key == "server":
            user_agent = list(value)[0]

    if defineTargetType(user_agent) == "Server":
        print(
            ("\033[1;32m[+] New live IP found on {}, It seems as a SIP Server ({}).\033[0m".format(target, user_agent)))
        writeFile(ops_ip_list, target + ";" + user_agent + ";SIP Server" + "\n")
        removeDuplicateLines(ops_ip_list)
    elif defineTargetType(user_agent) == "Client":
        print(("\033[1;32m[+] New live IP found on " + target + ", It seems as a SIP Client.\033[0m"))
        writeFile(ops_ip_list, target + ";" + user_agent + ";SIP Server" + "\n")
        removeDuplicateLines(ops_ip_list)

def print_red(text):
    print("\33[38;5;196m{}\33[0m".format(text))

def print_green(text):
    print("\033[1;32m{}\033[0m".format(text))

def warn(warning_message):
    print('\33[38;5;196m' + warning_message + '\33[0m')
    
def warn_and_exit(warning_message):
    print('\33[38;5;196m' + warning_message + '\33[0m')
    exit(0)
    
def decimal_to_octets(dec):
    return socket.inet_ntoa(struct.pack('!L', int(dec)))

def removeDuplicateLines(path):
    with open(path, 'r+') as f:
        unique = list(dict.fromkeys([line for line in f.readlines()]))
        f.seek(0)
        for line in unique: f.write(line)
        f.truncate()

def check_value_errors(value_errors):
    if len(value_errors) != 0:
        for err in value_errors: 
            warn(err)
        exit(0)
        
def check_ip_address(value):
    if '-' in value:
        for ip in value.split('-'):
            if '.' not in ip: raise argparse.ArgumentTypeError("{} is an invalid range IP address".format(ip))
            numbers = ip.split('.')
            if len(numbers) != 4: raise argparse.ArgumentTypeError("{} is an invalid range IP address".format(ip))
            for number in numbers:
                if int(number) > 255 or int(number) < 0: raise argparse.ArgumentTypeError("{} is an invalid range IP address".format(ip))
            return value
    if '/' in value:
        ip, subnet = value.split('/')
        if subnet != '24': raise argparse.ArgumentTypeError("{} is an invalid subnet IP address".format(value))
        if '.' not in ip: raise argparse.ArgumentTypeError("{} is an invalid subnet IP address".format(value))
        numbers = ip.split('.')
        if len(numbers) != 4: raise argparse.ArgumentTypeError("{} is an invalid subnet IP address".format(value))
        for number in numbers:
            if int(number) > 255 or int(number) < 0: raise argparse.ArgumentTypeError("{} is an invalid subnet IP address".format(value))
        return value
    if '.' not in value: raise argparse.ArgumentTypeError("{} is an invalid IP address".format(value))
    numbers = value.split('.')
    if len(numbers) != 4: raise argparse.ArgumentTypeError("{} is an invalid IP address".format(value))
    for number in numbers:
        if int(number) > 255 or int(number) < 0: raise argparse.ArgumentTypeError("{} is an invalid IP address".format(value))
    return value

