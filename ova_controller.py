from scapy.all import *
from scapy.layers.can import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from base64 import b64encode
import threading, time, json, getopt


conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}

load_contrib('isotp')
load_contrib('automotive.uds')
load_contrib('automotive.ecu')
load_contrib('cansocket')

use_SA = False
use_encrypt = False
use_sign = False

options = getopt.getopt(sys.argv[1:], '', ['security-access', 'encryption', 'signature'])

for opt, _ in options[0]:
    if opt == '--security-access':
        use_SA = True
    elif opt == '--encryption':
        use_encrypt = True
    elif opt == '--signature':
        use_sign = True

with open("firmware_gateway/firmware.sh", "rb") as fw:
    data = fw.read()

payload = {}

if use_SA:
    SA_secret = 0xdeadbeef00
    SA_sec_key = None

if use_sign:
    rsa_priv_key = RSA.import_key(open('private_key.pem').read())
    h = SHA256.new(data)
    sign = pkcs1_15.new(rsa_priv_key).sign(h)
    payload['sign'] = b64encode(sign).decode('utf-8')

if use_encrypt:
    aes_key = b"aI2#csCDackIH$13"
    cipher = AES.new(aes_key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    payload['data'] = b64encode(ciphertext).decode('utf-8')
    payload['nonce'] = b64encode(cipher.nonce).decode('utf-8')
    payload['tag'] = b64encode(tag).decode('utf-8')        
else:
    payload['data'] = b64encode(data).decode('utf-8')

payload = json.dumps(payload)

requests = [ \
    UDS()/UDS_DSC(diagnosticSessionType=0x2), \
    UDS()/UDS_RU(memorySizeLen=0x1, memoryAddressLen=0x4, memoryAddress4=0xaaaaaaaa, memorySize1=0x64), \
    UDS()/UDS_TD(blockSequenceCounter=0x0, transferRequestParameterRecord=payload), \
    UDS()/UDS_RTE(transferRequestParameterRecord=b'done'), \
    UDS()/UDS_ER()
]

if use_SA:
    requests.insert(1, UDS()/UDS_SA(securityAccessType=0x2))
    requests.insert(1, UDS()/UDS_SA(securityAccessType=0x1))

sock = ISOTPSocket('vcan0', sid=0x601, did=0x701, basecls=UDS)

for req in requests:
    if hasattr(req, 'securityAccessType') and req.securityAccessType == 0x2:
        req.securityKey = SA_sec_key.to_bytes(5, 'big')
        #req.securityKey = 0xEBDA8B87FB.to_bytes(5, 'big')

    resp = sock.sr1(req, timeout=0.1, verbose=False)
    time.sleep(0.3)

    if hasattr(resp, 'negativeResponseCode'):
        print(UDS.services[req.service] + " ... negative response!")
        print("Update failed!")
        exit(-1)
    elif req.service + 0x40 == resp.service:
        if hasattr(resp, 'securityAccessType') and resp.securityAccessType == 0x1:
            SA_sec_key = SA_secret ^ int(resp.securitySeed.hex(), 16)
        print(UDS.services[req.service] + "{}".format(' '*(30-(len(UDS.services[req.service])))) + "- OK")
    else:
        print("Error")
        exit(-1)
print("Update succeeded!")
