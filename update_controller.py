from scapy.all import *
from scapy.layers.can import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from base64 import b64decode
import threading, json, getopt


conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}

load_contrib('isotp')
load_contrib('automotive.uds')
load_contrib('automotive.ecu')
load_contrib('cansocket')

sock1 = ISOTPSocket('vcan0', sid=0x701, did=0x601, basecls=UDS)
transfer_ready = False
transfer_done = False
use_SA = False
use_encrypt = False
use_sign = False
sec_lvl = 0

options = getopt.getopt(sys.argv[1:], '', ['security-access', 'encryption', 'signature'])

for opt, _ in options[0]:
    if opt == '--security-access':
        use_SA = True
        sec_lvl = 1
    elif opt == '--encryption':
        use_encrypt = True
    elif opt == '--signature':
        use_sign = True

if use_SA:
    SA_request = False
    SA_secret = 0xdeadbeef00
    SA_sec_key = None

if use_encrypt:
    aes_key = b"aI2#csCDackIH$13"

if use_sign:
    rsa_pub_key = RSA.import_key(open('public_key.pub').read())


def update_fw(new_firmware):
    with open("firmware_ecu/firmware.sh", "wb") as new_fw:
        new_fw.write(new_firmware)
        print("Firmware updated")


def decrypt_data(data):
    global use_sign

    cipher = AES.new(aes_key, AES.MODE_OCB, nonce=data['nonce'])
    plaintext = cipher.decrypt_and_verify(data['data'], data['tag'])
    return plaintext


def verify_data(data, signature):
    h = SHA256.new(data)
    try:
        pkcs1_15.new(rsa_pub_key).verify(h, signature)
        print("Signature valid")
        return True
    except (ValueError, TypeError):
        print("Signature not valid")
        return False


def securityAccess(resp, req):
    global SA_sec_key, SA_secret, SA_request, answering_machine
    if req.service + 0x40 != resp.service or len(req) < 2:
        if req.service == 0x27 and resp.service == 0x7f:
            return True
        return
    if req.securityAccessType == 1:
        resp.securityAccessType = 1
        resp.securitySeed = get_random_bytes(5)
        SA_sec_key = SA_secret ^ int(resp.securitySeed.hex(), 16)
        SA_request = True
        print("Security Access request")
        return True
    elif req.securityAccessType == 2:
        if SA_request and req.securityKey == SA_sec_key.to_bytes(5, 'big'):
            resp.securityAccessType = 2
            SA_request = False
            print("Security Access granted")
            return True
        else:
            transfer_ready = False
            transfer_done = False
            SA_request = False
            answering_machine.ecu_state.reset()
            print("Security Access denied")
    return False


def transferData(resp, req):
    global transfer_ready, transfer_done, use_encrypt, use_sign

    if (req.service + 0x40) == resp.service and len(req) > 1:
        if req.blockSequenceCounter == 0 and transfer_ready:
            transfer_ready = False
            transfer_done = True
            data = req.transferRequestParameterRecord.decode("utf-8")
            b64_payload = json.loads(data)
            payload = { x: b64decode(b64_payload[x]) for x in b64_payload }
            if use_encrypt:
                data = decrypt_data(payload)
            else:
                data = payload['data']
            if use_sign:
                if not verify_data(data, payload['sign']):
                    return True
            update_fw(data)
            return True
    return False


def uploadRequest(resp, req):
    global transfer_ready, transfer_done

    if (req.service + 0x40) == resp.service and len(req) > 2:
        if req.memorySizeLen == 0x1 and req.memoryAddressLen == 0x4 and not transfer_done:
            transfer_ready = True
            print("Upload request")
            return True
    return False


def transferExit(resp, req):
    global transfer_done

    if (req.service + 0x40) == resp.service and len(req) > 1:
        if req.transferRequestParameterRecord == b'done' and transfer_done:
            transfer_done = False
            return True
    elif hasattr(resp, 'negativeResponseCode') and req.service == 0x37:
        if resp.negativeResponseCode == 0x22:
            return True
    return False


responseList = [ECUResponse(session=range(255), security_level=range(255), responses=UDS() / UDS_DSCPR(diagnosticSessionType=0x01)),
                ECUResponse(session=1, security_level=range(255), responses=UDS() / UDS_DSCPR(diagnosticSessionType=0x02)),

                ECUResponse(session=2, security_level=range(sec_lvl, 255), responses=UDS() / UDS_TDPR(), answers=transferData),
                ECUResponse(session=2, security_level=range(sec_lvl, 255), responses=UDS() / UDS_NR(requestServiceId=0x36, negativeResponseCode=0x22)),

                ECUResponse(session=2, security_level=range(sec_lvl, 255), responses=UDS() / UDS_RUPR(), answers=uploadRequest),
                ECUResponse(session=2, security_level=range(sec_lvl, 255), responses=UDS() / UDS_NR(requestServiceId=0x35, negativeResponseCode=0x13)),

                ECUResponse(session=2, security_level=range(sec_lvl, 255), responses=UDS() / UDS_RTEPR(transferResponseParameterRecord=b'ok'), answers=transferExit),
                ECUResponse(session=2, security_level=range(sec_lvl, 255), responses=UDS() / UDS_NR(requestServiceId=0x37, negativeResponseCode=0x22), answers=transferExit),

                ECUResponse(session=range(255), security_level=range(255), responses=UDS() / UDS_ERPR())
                ]

if use_SA:
    responseList.insert(0, ECUResponse(session=2, responses=UDS() / UDS_NR(requestServiceId=0x27, negativeResponseCode=0x33), answers=securityAccess))
    responseList.insert(0, ECUResponse(session=2, responses=UDS() / UDS_SAPR(), answers=securityAccess))

answering_machine = ECU_am(supported_responses=responseList, main_socket=sock1, basecls=UDS, timeout=None, verbose=False)
sim1 = threading.Thread(target=answering_machine)
sim1.start()


