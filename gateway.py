from scapy.all import *
from scapy.layers.can import *
import threading, time


conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}

load_contrib('isotp')
load_contrib('automotive.uds')
load_contrib('automotive.ecu')
load_contrib('cansocket')

#fw = open("firmware/random.txt", "rb")
#data = fw.read()
data = "hallo"

requests = [ \
    UDS()/UDS_DSC(diagnosticSessionType=0x2), \
    UDS()/UDS_SA(securityAccessType=0x2, securityKey=b'\x11'), \
    UDS()/UDS_RU(memorySizeLen=0x1, memoryAddressLen=0x4, memoryAddress4=0xaaaaaaaa, memorySize1=0x64), \
    UDS()/UDS_TD(blockSequenceCounter=0x0, transferRequestParameterRecord=data), \
    UDS()/UDS_RTE(transferRequestParameterRecord=b'done'), \
    UDS()/UDS_ER()
]

sock = ISOTPSocket('vcan0', sid=0x601, did=0x701, basecls=UDS)

for req in requests:
    resp = sock.sr1(req, timeout=0.1, verbose=False)
    time.sleep(1)
    if hasattr(req, 'negativeResponseCode'):
        print(UDS.services[req.service] + " ... negative response!")
        print("Update failed :(")
        exit(-1)
    elif req.service + 0x40 == resp.service:
        print(UDS.services[req.service] + " - OK")
    else:
        print("Error")
        exit(-1)
print("Update succeeded :)")
