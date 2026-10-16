#!/usr/bin/env python3
"""Offline IW8 empty-manifest signer/verifier, for 1.20-compatible native structure.
Requires: python -m pip install cryptography
No game process modifications; no private keys included.
"""
import argparse
import json
import struct
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

SIGNED_SIZE = 0xDC00C
MAX_COUNT = 0x800
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=8)

def native_empty_bytes(obj):
    if type(obj) is not dict:
        raise ValueError('manifest must be a JSON object')
    count = obj.get('count')
    if type(count) is not int or count != 0:
        raise ValueError('only count=0 is implemented; entry serialization is not established')
    buf = bytearray(SIGNED_SIZE)
    for name in ('manifestver', 'dataverff', 'purgeCache'):
        value = obj.get(name)
        if type(value) is not int or not 0 <= value <= 0xFFFF:
            raise ValueError(f'{name} must be an unsigned 16-bit integer')
    struct.pack_into('<IHHH', buf, 0xDC000, count, obj['manifestver'], obj['dataverff'], obj['purgeCache'])
    return bytes(buf)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    ver=sub.add_parser('verify',help='verify an empty manifest against a DER or PEM public key')
    ver.add_argument('--manifest',type=Path,required=True)
    ver.add_argument('--public-key',type=Path,required=True)
    sign=sub.add_parser('sign',help='sign an empty manifest; specify actual client dataverff explicitly')
    sign.add_argument('--private-key',type=Path,required=True)
    sign.add_argument('--output',type=Path,required=True)
    sign.add_argument('--dataverff',type=int,required=True)
    sign.add_argument('--manifestver',type=int,default=1)
    sign.add_argument('--purge-cache',type=int,choices=(0,1),default=0)
    args=p.parse_args()
    if args.command=='sign':
        key=serialization.load_pem_private_key(args.private_key.read_bytes(),password=None)
        if not isinstance(key,rsa.RSAPrivateKey) or key.key_size != 2048:
            p.error('expected an RSA-2048 private key')
        m={'count':0,'manifestver':args.manifestver,'dataverff':args.dataverff,'purgeCache':args.purge_cache}
        signature=key.sign(native_empty_bytes(m),PSS,hashes.SHA256())
        m['signature']=signature.hex()
        args.output.write_text(json.dumps(m,separators=(',',':'))+'\n',encoding='utf-8')
        print(f'signed {args.output} using RSA-PSS/SHA256, 8-byte salt, zero entries')
    else:
        m=json.loads(args.manifest.read_text(encoding='utf-8'))
        payload=native_empty_bytes(m)
        signature=bytes.fromhex(m['signature'])
        if len(signature)!=256:
            p.error('signature is not 256 bytes')
        keydata=args.public_key.read_bytes()
        try: key=serialization.load_der_public_key(keydata)
        except ValueError: key=serialization.load_pem_public_key(keydata)
        try:
            key.verify(signature,payload,PSS,hashes.SHA256())
        except InvalidSignature:
            p.error('INVALID: signature does not match the selected public key and native structure')
        print('VALID: RSA-PSS/SHA-256 over native zero-entry 0xDC00C structure')

if __name__=='__main__':
    main()
