import ipaddress, random, os

def readFile(file):
    f = open(file, "r")
    content = f.read()
    f.close()
    return content
    
def writeFile(file,content):
    f = open(file, "a+")
    f.write(content)
    f.close()

def randomIPAddressFromNetwork(IP, Netmask, Network):
    network = ""
    if Network:
        network = Network
    else:
        network = "{0}/{1}".format(str(IP), str(Netmask))

    targetNetwork = ipaddress.IPv4Network(unicode(network), strict=False)
    ipCount = int(targetNetwork.num_addresses)
    firstIpAddress = targetNetwork.network_address
    randomInt = random.randint(0,ipCount-1)
    randomIpAddress = (firstIpAddress + randomInt)
    return str(randomIpAddress.exploded)
    
def randomIPAddress():
    return ".".join([str(random.randrange(1,255)),str(random.randrange(1,255)),str(random.randrange(1,255)),str(random.randrange(1,255))]) 
    
def promisc(state,iface):
    # Manage interface promiscuity. valid states are on or off
    ret =  os.system("ip link set {0} promisc {1}".format(iface, state))
    if ret == 1:
        print ("You must run this script with root permissions.")
        
def printProgressBar (iteration, total, prefix = '', decimals = 1, length = 100, fill = '|'):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print '%s |%s| %s%%\r' % (prefix, bar, percent),
    if iteration == total: 
        print ''