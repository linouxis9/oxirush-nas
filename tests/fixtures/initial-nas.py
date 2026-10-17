#!/usr/bin/env python3
"""Initial NAS messages as a UE with a 5G NAS security context sends them (TS 24.501 4.4.6),
computed without oxirush-nas and without oxirush-security: the key derivation of TS 33.501
A.8, AES-CMAC and AES-CTR as TS 33.501 D.3.1.3 and D.2.1.3 refer to TS 33.401 B.2.3 and
B.1.3, with hashlib, hmac and the `cryptography` package. The messages are written by hand
from clause 8.2 and 9.11 of TS 24.501. One line each: name, KAMF, integrity algorithm,
ciphering algorithm, uplink NAS COUNT, the complete message, the protected message.
128-NIA2 with 128-NEA2 and with 5G-EA0; algorithms 1 and 3 are not computed here."""
import hmac, hashlib
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def kdf(kamf, distinguisher, algorithm):          # TS 33.501 A.8: FC = 0x69
    s = bytes([0x69, distinguisher, 0x00, 0x01, algorithm, 0x00, 0x01])
    return hmac.new(kamf, s, hashlib.sha256).digest()[16:]

def head(count, bearer, direction):
    return count.to_bytes(4, 'big') + bytes([(bearer << 3) | (direction << 2), 0, 0, 0])

def cmac(key, count, bearer, direction, octets):   # 128-NIA2
    c = CMAC(algorithms.AES(key)); c.update(head(count, bearer, direction) + octets)
    return c.finalize()[:4]

def ctr(key, count, bearer, direction, octets):    # 128-NEA2
    e = Cipher(algorithms.AES(key), modes.CTR(head(count, bearer, direction) + bytes(8))).encryptor()
    return e.update(octets) + e.finalize()

x = bytes.fromhex
GUTI = x('000bf202f839010040c0000001')              # 5G-GUTI 208-93, AMF 1/1/0, TMSI c0000001
S_TMSI = x('0007f40040c0000001')                    # 5G-S-TMSI, AMF set 1, pointer 0
CASES = [
    # name, cleartext IEs alone, the other IEs, how the others are sent
    # REGISTRATION REQUEST: mobility registration updating with FOR, ngKSI 0; requested NSSAI
    ('registration-request', x('7e00410a') + GUTI, x('2f050401010203'), 'container'),
    # SERVICE REQUEST: service type "data", ngKSI 0; uplink data status of PSI 5
    ('service-request', x('7e004c10') + S_TMSI, x('40022000'), 'container'),
    # DEREGISTRATION REQUEST from the UE: 3GPP access, ngKSI 0; unavailability information
    ('deregistration-request', x('7e004501') + GUTI, x('3c0100'), 'container'),
    # CONTROL PLANE SERVICE REQUEST: mobile originating, ngKSI 0; payload container type
    # "CIoT user data container", payload container and PDU session ID 5, which its container
    # has without the cleartext IEs (4.4.6 b) 2) ii), 9.11.3.33)
    ('control-plane-service-request', x('7e004f01'), x('847b0002a1b21205'), 'ies'),
    # CONTROL PLANE SERVICE REQUEST whose only other IE is the CIoT small data container:
    # control plane user data of PDU session 5
    ('control-plane-service-request-small-data', x('7e004f01'), x('6f0305a1b2'), 'value'),
    # A REGISTRATION REQUEST with cleartext IEs alone has no container
    ('registration-request-cleartext', x('7e00410a') + GUTI + x('2e02f0f0'), b'', 'none'),
]
KAMF = bytes(range(0x40, 0x60))
BEARER, UPLINK = 1, 0                              # 3GPP access (TS 33.501 6.4.2.2), uplink
for ea in (2, 0):
    kint, kenc = kdf(KAMF, 0x02, 2), kdf(KAMF, 0x01, ea)
    cipher = (lambda count, octets: ctr(kenc, count, BEARER, UPLINK, octets)) if ea else (lambda count, octets: octets)
    for place, (name, cleartext, others, how) in enumerate(CASES):
        count = 0x000100 * place + 0x2a + place    # with an overflow counter that is not zero
        complete = cleartext + others
        if how in ('container', 'ies'):                # the complete message, or its other IEs
            ciphered = cipher(count, complete if how == 'container' else others)
            outer = cleartext + b'\x71' + len(ciphered).to_bytes(2, 'big') + ciphered
        elif how == 'value':                         # the value of the IE alone: after IEI and length
            outer = cleartext + others[:2] + cipher(count, others[2:])
        else:
            outer = complete
        covered = bytes([count & 0xff]) + outer
        pdu = x('7e01') + cmac(kint, count, BEARER, UPLINK, covered) + covered
        print('\t'.join([f'{name}-nea{ea}', KAMF.hex(), '2', str(ea), str(count), complete.hex(), pdu.hex()]))
