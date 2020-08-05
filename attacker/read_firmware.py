from scapy.sendrecv import sniff
from scapy.main import load_contrib
from scapy.layers.can import *
import json, base64, sys

conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}

load_contrib('cansocket')
load_contrib('isotp')
load_contrib('automotive.uds')
load_contrib('automotive.ecu')

if len(sys.argv) < 2:
    iface = "vcan0"
else:
    iface = sys.argv[1]

sock = CANSocket(iface)

print("Sniffing bus ...")

def print_data(pkt):
    if pkt.service == 0x36:
        json_data = (pkt.transferRequestParameterRecord).decode('utf-8')
        b64_data = json.loads(json_data)
        data = base64.b64decode(b64_data['data'])
        try:
            print("Transmitted data:\n" + data.decode('utf-8'))
        except:
            print("Could not decode transmitted data:")
            print(data)

udsmsgs = sniff(session=ISOTPSession, session_kwargs={"basecls": UDS}, opened_socket=sock, prn=print_data)


        