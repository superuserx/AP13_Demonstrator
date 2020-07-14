from scapy.all import *
from scapy.layers.can import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from base64 import b64encode
import threading, time, json


conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}

load_contrib('isotp')
load_contrib('automotive.uds')
load_contrib('automotive.ecu')
load_contrib('cansocket')

with open("firmware_gateway/firmware.sh", "rb") as fw:
    data = fw.read()

SA_secret = 0xdeadbeeeef
SA_sec_key = None

aes_key = b"passwordpassword"
cipher = AES.new(aes_key, AES.MODE_OCB)
ciphertext, tag = cipher.encrypt_and_digest(data)

rsa_priv_key = RSA.import_key(open('private_key.pem').read())
h = SHA256.new(data)
sign = pkcs1_15.new(rsa_priv_key).sign(h)

payload = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, ciphertext, tag, sign) ]
enc_data = json.dumps(dict(zip(['nonce', 'ciphertext', 'tag', 'sign'], payload)))

requests = [ \
    UDS()/UDS_DSC(diagnosticSessionType=0x2), \
    UDS()/UDS_SA(securityAccessType=0x1), \
    UDS()/UDS_SA(securityAccessType=0x2), \
    UDS()/UDS_RU(memorySizeLen=0x1, memoryAddressLen=0x4, memoryAddress4=0xaaaaaaaa, memorySize1=0x64), \
    UDS()/UDS_TD(blockSequenceCounter=0x0, transferRequestParameterRecord=enc_data), \
    UDS()/UDS_RTE(transferRequestParameterRecord=b'done'), \
    UDS()/UDS_ER()
]

sock = ISOTPSocket('vcan0', sid=0x601, did=0x701, basecls=UDS)

for req in requests:
    if hasattr(req, 'securityAccessType') and req.securityAccessType == 0x2:
        req.securityKey = SA_sec_key.to_bytes(5, 'big')

    resp = sock.sr1(req, timeout=0.1, verbose=False)
    time.sleep(0.1)

    if hasattr(resp, 'negativeResponseCode'):
        print(UDS.services[req.service] + " ... negative response!")
        print("Update failed :(")
        exit(-1)
    elif req.service + 0x40 == resp.service:
        if hasattr(resp, 'securityAccessType') and resp.securityAccessType == 0x1:
            SA_sec_key = SA_secret ^ int(resp.securitySeed.hex(), 16)
        print(UDS.services[req.service] + " - OK")
    else:
        print("Error")
        exit(-1)
print("Update succeeded :)")
