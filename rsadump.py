import argparse
import os
import pathlib
import base64
import mmap
import re
import struct
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from dataclasses import dataclass

@dataclass
class RsaBlob:
    offset: int
    e: int
    n: int
    p: int
    q: int
    format: str

    def is_valid(self) -> bool:
        return self.p * self.q == self.n

def string_or_path(value):
    if os.path.isfile(value):
        try:
            with open(value,'r',encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            raise argparse.ArgumentTypeError(f"Could not read file '{value}': {e}")
    return value

parser = argparse.ArgumentParser()
parser.add_argument("-d","--dump", type=pathlib.Path, required=True)
parser.add_argument("-m","--modulus", type=string_or_path, required=True)
parser.add_argument("-s", "--session-key", type=pathlib.Path, required=True)

def byte_length_of_base64(value):
    return len(base64.b64decode(value.strip()))

def find_rsa2_blobs(mm, length):
    bitlen_bytes = (length*8).to_bytes(4, 'little')
    for m in re.finditer(b'RSA2' + bitlen_bytes,mm):
        yield m.start()

def looks_like_cng(mm, offset, length):
    _, bitlen, cb_exp, cb_mod, cb_p, cb_q = struct.unpack_from('<4sIIIII', mm, offset)
    return (1 <= cb_exp <= 8 and cb_mod == length
            and cb_p == cb_q == length // 2)

def looks_like_cryptoapi(mm, offset):
    _, bitlen, e = struct.unpack_from('<4sII', mm, offset)
    return e > 1 and e % 2 == 1

def parse_cryptoapi_blob(mm, offset):
    magic, bitlen, e = struct.unpack_from('<4sII', mm, offset)
    mod_start = offset + 12
    L = bitlen // 8
    H = bitlen // 16
    p_start = mod_start + L
    q_start = p_start + H
    n = int.from_bytes(mm[mod_start : mod_start + L], 'little')
    p = int.from_bytes(mm[p_start : p_start + H], 'little')
    q = int.from_bytes(mm[q_start : q_start + H], 'little')
    return RsaBlob(offset, e, n, p, q, 'cryptoapi')

def parse_cng_blob(mm, offset):
    magic, bitlen, cb_exp, cb_mod, cb_p, cb_q = struct.unpack_from('<4sIIIII', mm, offset)
    exp_start = offset + 24
    mod_start = exp_start + cb_exp
    p_start = mod_start + cb_mod
    q_start = p_start + cb_p
    e = int.from_bytes(mm[exp_start : exp_start + cb_exp], 'big')
    n = int.from_bytes(mm[mod_start : mod_start + cb_mod], 'big')
    p = int.from_bytes(mm[p_start : p_start + cb_p], 'big')
    q = int.from_bytes(mm[q_start : q_start + cb_q], 'big')
    return RsaBlob(offset, e, n, p, q, 'cng')

def build_private_key(blob: RsaBlob):
    if not blob.is_valid(): 
        raise ValueError(f"p*q != n for blob at offset {blob.offset}")

    phi = (blob.p-1)*(blob.q-1) # Eulers Totient
    d = pow(blob.e, -1, phi) # Modular inverse
    key = RSA.construct((blob.n, blob.e, d, blob.p, blob.q))
    with open(f'key_{blob.offset}.pem', "wb") as f:
        f.write(key.export_key())
        print(f"Private Key created")
    return key

def decrypt_session_key(key, path):
    with open(path,"rb") as f:
        session_key = PKCS1_OAEP.new(key).decrypt(f.read())
        return session_key

def map_dump(dumpfile):
    with open(dumpfile,"rb") as f:
        return mmap.mmap(f.fileno(),length=0, access=mmap.ACCESS_READ)

def main():
    args = parser.parse_args()
    mod_length = byte_length_of_base64(args.modulus)
    print(f'+ Check Length of Modulus\n {mod_length}')
    mapped_dump = map_dump(args.dump)
    modulus = int.from_bytes(base64.b64decode(args.modulus.strip()),'big')

    rsa_blobs = []
    for offset in find_rsa2_blobs(mapped_dump, mod_length):
        if looks_like_cng(mapped_dump, offset, mod_length):
            rsa_blobs.append(parse_cng_blob(mapped_dump, offset))
        elif looks_like_cryptoapi(mapped_dump, offset):
            rsa_blobs.append(parse_cryptoapi_blob(mapped_dump, offset))

    matched_blobs = [blob for blob in rsa_blobs if blob.n == modulus]
    valid_blobs = [blob for blob in matched_blobs if blob.is_valid()]

    for fmt in ('cng', 'cryptoapi'):
        found   = [b for b in rsa_blobs     if b.format == fmt]
        matched = [b for b in matched_blobs if b.format == fmt]
        valid   = [b for b in valid_blobs   if b.format == fmt]
        print(f'+ {fmt}: {len(found)} blobs, {len(matched)} matching the modulus, {len(valid)} valid')

    unique_blobs = []
    seen = set()
    for blob in valid_blobs:
        fingerprint = (blob.e, blob.n, blob.p, blob.q)
        if fingerprint not in seen:
            seen.add(fingerprint)
            unique_blobs.append(blob)
        else:
            print(f'Duplicate {blob.format} blob @ offset {blob.offset}')

    if unique_blobs:
        for blob in unique_blobs:
            key = build_private_key(blob)
            session_key = decrypt_session_key(key, args.session_key)
            print(f'+ Session key ({len(session_key)} bytes): {base64.b64encode(session_key).decode()}')
    else:
        print("No usable key found")

    mapped_dump.close()

if __name__ == '__main__':
    main()