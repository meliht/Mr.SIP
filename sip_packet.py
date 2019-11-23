"""
#####################################################################################################
        ################################   Importing Packages  ################################ 
#####################################################################################################
"""

import random, string, os, socket, re
from time import sleep
from scapy.all import *

"""
#####################################################################################################
        ################################   SIP Packet Creator Code  ################################ 
#####################################################################################################
"""

class sip_packet:
    """
    [[server_ip]]
    [[server_port]]
    [[client_ip]]
    [[client_port]]
    [[from_user]]
    [[to_user]]
    [[user_agent]]
    [[sp_user]]
    [[expire_duration]]
    [[call_id]]
    [[branch_value]]
    [[tag_value]]
    """
    def __init__(self, method, server_ip, server_port,
                 client_ip, from_user = "", to_user = "",
                 user_agent = "", sp_user = "", protocol = "tcp", expire_duration=3600, wait=False):
        self.method = method
        self.protocol = protocol
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_ip = client_ip
        self.from_user = from_user
        self.to_user = to_user
        self.user_agent = user_agent
        self.sp_user = sp_user
        self.expire_duration = expire_duration
        self.wait = wait
        
    TRYING = '100'
    RINGING = '180'
    OKEY = '200'
    BADREQUEST = '400'
    AUTHREQ = '401'
    INVALIDPASS = '403'
    NOTFOUND = '404'
    NOTALLOWED = '405'
    PROXYAUTHREQ = '407'
    UNAVAILABLE = '480'
    INEXISTENTTRANSACTION = '481'
    SERVICEUN = '503'
    DECLINED = '603'
    
    method_location = os.path.join(os.getcwd(), "method")
    client_port = random.randint(10000,65535)
    
    @staticmethod
    def get_rand_call_id():
        prefix = ''.join(random.sample(string.digits + string.ascii_lowercase, 27))
        return "{0}{1}".format(str(prefix), str(random.randrange(10000, 99999)))

    @staticmethod
    def get_rand_branch():
        prefix = ''.join(random.sample(string.digits, 10))
        return "z9hG4bK-{0}".format(str(prefix))

    @staticmethod
    def get_rand_tag():
        prefix = random.randint(100000,999999)
        return "{0}".format(str(prefix))

    def fill_packet_data(self, text):
        var_dict = {'[[server_ip]]':str(self.server_ip),
                  '[[server_port]]': str(self.server_port),
                  '[[client_ip]]': str(self.client_ip),
                  '[[client_port]]': str(self.client_port),
                  '[[from_user]]': str(self.from_user),
                  '[[to_user]]': str(self.to_user),
                  '[[user_agent]]': str(self.user_agent),
                  '[[sp_user]]': str(self.sp_user),
                  '[[expire_duration]]': str(self.expire_duration),
                  '[[call_id]]': str(self.get_rand_call_id()),
                  '[[branch_value]]': str(self.get_rand_branch()),
                  '[[tag_value]]': str(self.get_rand_tag())}

        for key, value in var_dict.items():
            text = text.replace(key, value)
        return text.encode()

    def generate_packet(self):
        # try:
        f = open(os.path.join(self.method_location, "{0}.message".format(self.method)), "r")
        packet_data = f.read()
        packet_data = self.fill_packet_data(packet_data)

        if self.protocol == "socket":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.connect((str(self.server_ip), int(self.server_port)))
            s.sendall(packet_data)
            if self.wait:
                buff,srcaddr = s.recvfrom(8192)
                s.close()
                status = self.getResponse(buff)
                return {"status": True, "response": status}
            else:
                s.close()
                return {"status": True}

        elif self.protocol == "scapy":
            pkt = IP(src=self.client_ip, dst=self.server_ip) / UDP(sport=int(self.client_port), dport=int(self.server_port)) / packet_data
            send(pkt, iface=conf.iface)
            return {"status": True}
        # except Exception as e:
        #     print(e)
        #     return {"status": False}


    def getResponse(self, resp):
        import re
        nl = '\r\n\r\n'
        headers_nl = '\r*\n(?![\t\x20])'
        resp = resp.decode()
        if nl in resp:
            header,body = resp.split(nl,1)
        else:
            header = resp
            body = ''
        headers = re.split(headers_nl, header)
        
        if len(headers) > 1:
            response = dict()
            first_line = headers[0].split(' ',2)
            if len(first_line) == 3:
                version,code,description = first_line
            else:
                print ('Could not parse the first header line: {0}'.format(first_line))
                return response
            try:
                response['code'] = int(code)
            except ValueError:
                return response
                
            
            response['headers'] = dict()
            for headerline in headers[1:]:
                nl = ':'
                if nl in headerline:
                    tmpname,tmpval = headerline.split(nl,1)
                    name = tmpname.lower().strip()
                    val =  map(lambda x: x.strip(),tmpval.split(','))
                else:
                    name,val = headerline.lower(),None
                response['headers'][name] = val
            response['body'] = body
            return response


