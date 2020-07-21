from scapy.sendrecv import sniff
from scapy.main import load_contrib
from scapy.layers.can import *
import json, base64

conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}

load_contrib('cansocket')
load_contrib('isotp')
load_contrib('automotive.uds')
load_contrib('automotive.ecu')

sock = CANSocket('vcan0')
 
udsmsgs = sniff(session=ISOTPSession, session_kwargs={"basecls": UDS}, timeout=5, opened_socket=sock)

for m in udsmsgs:
    if m.service == 0x36:
        json_data = (m.transferRequestParameterRecord).decode('utf-8')
        b64_data = json.loads(json_data)
        data = base64.b64decode(b64_data['data'])
        try:
            print(data.decode('utf-8'))
        except:
            print("Could not decode data:")
            print(data)

        