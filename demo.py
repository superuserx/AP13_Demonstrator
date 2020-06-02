from scapy.all import *
from scapy.layers.can import *
import threading


conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}

load_contrib('isotp')
load_contrib('automotive.uds')
load_contrib('automotive.ecu')
load_contrib('cansocket')

sock1 = ISOTPSocket('vcan0', sid=0x701, did=0x601, basecls=UDS)
transfer_ready = False
transfer_done = False

def securityAccess(resp, req):
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


def transferData(resp, req):
    global transfer_ready, transfer_done

    if (req.service + 0x40) == resp.service and len(req) > 1:
        if req.blockSequenceCounter == 0 and transfer_ready:
            transfer_ready = False
            transfer_done = True
            #new_fw = open("firmware/rec_random.txt", "wb")
            data = req.transferRequestParameterRecord.decode("utf-8")
            print(data)
            #new_fw.write(data)
            #new_fw.close()
            return True
    return False


def uploadRequest(resp, req):
    global transfer_ready, transfer_done

    if (req.service + 0x40) == resp.service and len(req) > 2:
        if req.memorySizeLen == 0x1 and req.memoryAddressLen == 0x4 and not transfer_done:
            transfer_ready = True
            print("Ready for Transfer")
            return True
    return False


def transferExit(resp, req):
    global transfer_done

    if (req.service + 0x40) == resp.service and len(req) > 1:
        if req.transferRequestParameterRecord == b'done' and transfer_done:
            transfer_done = False
            return True
    elif hasattr(resp, 'negativeResponseCode'):
        if resp.negativeResponseCode == 0x22:
            return True
    return False


responseList = [ECUResponse(session=2, responses=UDS() / UDS_SAPR(), answers=securityAccess),
                ECUResponse(session=2, responses=UDS() / UDS_NR(requestServiceId=0x27, negativeResponseCode=0x33), answers=securityAccess),

                ECUResponse(session=range(255), security_level=range(255), responses=UDS() / UDS_DSCPR(diagnosticSessionType=0x01)),
                ECUResponse(session=1, security_level=range(255), responses=UDS() / UDS_DSCPR(diagnosticSessionType=0x02)),

                ECUResponse(session=2, security_level=range(1, 255), responses=UDS() / UDS_TDPR(), answers=transferData),
                ECUResponse(session=2, security_level=range(1, 255), responses=UDS() / UDS_NR(requestServiceId=0x36, negativeResponseCode=0x22)),

                ECUResponse(session=2, security_level=range(1, 255), responses=UDS() / UDS_RUPR(), answers=uploadRequest),
                ECUResponse(session=2, security_level=range(1, 255), responses=UDS() / UDS_NR(requestServiceId=0x35, negativeResponseCode=0x13)),

                ECUResponse(session=2, security_level=range(1, 255), responses=UDS() / UDS_RTEPR(transferResponseParameterRecord=b'ok'), answers=transferExit),
                ECUResponse(session=2, security_level=range(1, 255), responses=UDS() / UDS_NR(requestServiceId=0x37, negativeResponseCode=0x22), answers=transferExit),
                ]

answering_machine1 = ECU_am(supported_responses=responseList, main_socket=sock1, basecls=UDS, timeout=None)
sim1 = threading.Thread(target=answering_machine1)
sim1.start()


