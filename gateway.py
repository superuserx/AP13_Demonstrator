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
    UDS()/UDS_SA(securityAccessType=2, securityKey=b'\x11'), \
    UDS()/UDS_RU(memorySizeLen=0x1, memoryAddressLen=0x4, memoryAddress4=0xaaaaaaaa, memorySize1=0x64), \
    UDS()/UDS_TD(blockSequenceCounter=0x0, transferRequestParameterRecord=data), \
    UDS()/UDS_RTE(transferRequestParameterRecord=b'done')
]

sock = ISOTPSocket('vcan0', sid=0x601, did=0x701, basecls=UDS)

for req in requests:
    resp = sock.sr1(req, timeout=0.1, verbose=False)
    time.sleep(1)
    if hasattr(req, 'negativeResponseCode'):
        print(UDS.services[req.service] + " ... ERROR")
        print("Update failed :(")
        exit(-1)
    elif req.service + 0x40 == resp.service:
        print(UDS.services[req.service] + " ... OK")
print("Update succeeded :)")



#print("Switching to programming session...")
#time.sleep(1)
#dsc_resp = sock.sr1(dsc, timeout=0.1, verbose=False)
#if not hasattr(dsc_resp, 'negativeResponseCode'):
#    if dsc.service + 0x40 == dsc_resp.service and dsc_resp.diagnosticSessionType == 0x2:
#        print("Requesting Security Access...")
#        time.sleep(1)
#        sa_resp = sock.sr1(sa, timeout=0.1, verbose=False)
#        if not hasattr(sa_resp, 'negativeResponseCode'):
#            if sa.service + 0x40 == sa_resp.service and sa_resp.securityAccessType == 0x2:
#                print("Requesting Upload...")
#                time.sleep(1)
#                ru_resp = sock.sr1(ru, timeout=0.1, verbose=False)
#                if not hasattr(ru_resp, 'negativeResponseCode'):
#                    if ru.service + 0x40 == ru_resp.service:
#                        print("Requesting data transfer...")
#                        time.sleep(1)
#                        td_resp = sock.sr1(td, timeout=0.1, verbose=False)
#                        if not hasattr(td_resp, 'negativeResponseCode'):
#                            if td.service + 0x40 == td_resp.service:
#                                rte_resp = sock.sr1(rte, timeout=0.1, verbose=False)
#                                print("Finished data tranfer")
#                                time.sleep(1)
#                                if rte.service + 0x40 == rte_resp.service and rte_resp.transferResponseParameterRecord == b'ok':
#                                    print("Update succeeded :)")
#                                    exit(0)
#print("Update failed :(")
#exit(-1)