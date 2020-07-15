from scapy.all import *
from scapy.layers.can import *

conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}

load_contrib('cansocket')
load_contrib('isotp')
load_contrib('automotive.uds')

sock1 = CANSocket('vcan0', basecls=UDS)
 