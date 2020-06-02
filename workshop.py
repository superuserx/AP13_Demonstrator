from scapy.all import *
from scapy.layers.can import *
import threading


conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}

load_contrib('isotp')
load_contrib('automotive.uds')
load_contrib('automotive.ecu')
load_contrib('cansocket')

can_iface = 'vcan0'

sock1 = ISOTPSocket(can_iface, sid=0x701, did=0x601, basecls=UDS)
sock2 = ISOTPSocket(can_iface, sid=0x702, did=0x602, basecls=UDS)
sock3 = ISOTPSocket(can_iface, sid=0x703, did=0x603, basecls=UDS)
sock4 = ISOTPSocket(can_iface, sid=0x704, did=0x604, basecls=UDS)
sock5 = ISOTPSocket(can_iface, sid=0x705, did=0x605, basecls=UDS)


def customAnswer(resp, req):
    if req.service + 0x40 != resp.service or len(req) < 2:
        if req.service == 0x27 and resp.service == 0x7f:
            return True
        return False
    if req.securityAccessType == 1:
        print('Seed request')
        resp.securityAccessType = 1
        resp.securitySeed = bytes([0xab])
        return True
    elif req.securityAccessType == 2:
        print('Key received')
        print(req.securityKey)
        if req.securityKey == bytes([0x11]):
            resp.securityAccessType = 2
            return True
    return False


responseList = [ECUResponse(session=2, responses=UDS() / UDS_SAPR(), answers=customAnswer),
                ECUResponse(session=2, responses=UDS() / UDS_NR(requestServiceId=0x27, negativeResponseCode=0x33), answers=customAnswer),

                ECUResponse(session=2, responses=UDS(service=0x51)), #ERPR
                ECUResponse(session=1, responses=UDS(service=0x51)), #ERPR
                ECUResponse(session=1, responses=UDS(service=0x7e)), #TPPR

                ECUResponse(session=range(255), security_level=range(255), responses=UDS() / UDS_ERPR(resetType='hardReset')),
                ECUResponse(session=range(255), security_level=range(255), responses=UDS() / UDS_DSCPR(diagnosticSessionType=0x01)),
                ECUResponse(session=range(255), security_level=range(255), responses=UDS() / UDS_DSCPR(diagnosticSessionType=0x02)),

                ECUResponse(session=1, responses=UDS() / UDS_RDBIPR(dataIdentifier=0x20) / Raw(b'GIN SALABIM!')),
                ECUResponse(session=1, responses=UDS() / UDS_NR(requestServiceId=0x22, negativeResponseCode=0x13)),
                ECUResponse(session=1, security_level=range(0, 255), responses=UDS() / UDS_NR(requestServiceId=0x22, negativeResponseCode=0x7f)),
                ECUResponse(session=2, security_level=range(1, 255), responses=UDS() / UDS_RDBIPR(dataIdentifier=0x2a) / Raw(b'Step aside coffee -- this is a job for Gin!')),
                ECUResponse(session=2, security_level=range(1, 255), responses=UDS() / UDS_NR(requestServiceId=0x22, negativeResponseCode=0x13)),

                ECUResponse(session=1, responses=UDS() / UDS_NR(requestServiceId=0x28, negativeResponseCode=0x22)),
                ECUResponse(session=1, responses=UDS() / UDS_NR(requestServiceId=0x83, negativeResponseCode=0x22)),
                ECUResponse(session=1, responses=UDS() / UDS_NR(requestServiceId=0x85, negativeResponseCode=0x13)),

                ECUResponse(session=1, responses=UDS() / UDS_NR(requestServiceId=0x86, negativeResponseCode=0x7f)),
                ECUResponse(session=2, responses=UDS() / UDS_NR(requestServiceId=0x86, negativeResponseCode=0x22)),
                ECUResponse(session=1, responses=UDS() / UDS_NR(requestServiceId=0x87, negativeResponseCode=0x22)),
                ]

answering_machine1 = ECU_am(supported_responses=responseList, main_socket=sock1, basecls=UDS, timeout=None)
answering_machine2 = ECU_am(supported_responses=responseList, main_socket=sock2, basecls=UDS, timeout=None)
answering_machine3 = ECU_am(supported_responses=responseList, main_socket=sock3, basecls=UDS, timeout=None)
answering_machine4 = ECU_am(supported_responses=responseList, main_socket=sock4, basecls=UDS, timeout=None)
answering_machine5 = ECU_am(supported_responses=responseList, main_socket=sock5, basecls=UDS, timeout=None)

sim1 = threading.Thread(target=answering_machine1)
sim2 = threading.Thread(target=answering_machine2)
sim3 = threading.Thread(target=answering_machine3)
sim4 = threading.Thread(target=answering_machine4)
sim5 = threading.Thread(target=answering_machine5)

sim1.start()
sim2.start()
sim3.start()
sim4.start()
sim5.start()
