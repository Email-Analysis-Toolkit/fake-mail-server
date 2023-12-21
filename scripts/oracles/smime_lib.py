#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2023 Fabian Ising
#
# Distributed under terms of the MIT license.

"""

"""
from asn1crypto import cms
from base64 import b64decode,b64encode
from OpenSSL import crypto
from binascii import *
from Crypto.Cipher import PKCS1_v1_5
# from Crypto.PublicKey import RSA
from Crypto.Cipher import DES3, ARC4, AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.utils import int_to_bytes

algo_map = {
        '1.2.840.113549.3.7': DES3,
        '1.2.840.113549.3.4': ARC4,
        '2.16.840.1.101.3.4.1.42': AES,
        '2.16.840.1.101.3.4.1.2': AES
}

def rsa_decrypt(encrypted_key, priv_key):
    padded_key = int_to_bytes(pow(int.from_bytes(encrypted_key, byteorder='big'), priv_key.private_numbers().d, priv_key.private_numbers().public_numbers.n))
    return bytes([0] + list(padded_key))

def pkcs1_v1_5_decrypt(encrypted_key, priv_key):
    padded_key = rsa_decrypt(encrypted_key, priv_key)
    if padded_key[0] != 0 or padded_key[1] != 2:
        raise Exception("PKCS#1v1.5 padding wrong!")
    else:
        padded_key = padded_key[2:]
        for i, c in enumerate(padded_key):
            if c == 0:
                return padded_key[i+1:]
    return []

def decrypt(body, path="smime_key.pem"):
    priv_key = load_key_from_pem(path)
    body = b64decode(body)
    body = cms.ContentInfo.load(body)
    enc_key = bytes(body["content"]["recipient_infos"][0].chosen["encrypted_key"])
    enc_key = bytearray(enc_key)
    dec_key = pkcs1_v1_5_decrypt(enc_key, priv_key)
    iv     = bytes(body["content"]["encrypted_content_info"]["content_encryption_algorithm"]["parameters"])
    cipher_text = bytes(body["content"]["encrypted_content_info"]["encrypted_content"])
    if dec_key is None:
        #Wrong padding?!
        raise Exception("Wrong padding")
    algorithm_id     = str(body["content"]["encrypted_content_info"]["content_encryption_algorithm"]['algorithm'])
    algorithm = algo_map[algorithm_id]
    if algorithm == DES3 or algorithm == AES: 
        cipher = algorithm.new(dec_key, algorithm.MODE_CBC, iv)
    else:
        cipher = algorithm.new(dec_key)
    
    plain = cipher.decrypt(cipher_text)

    if algorithm == DES3: 
        plain = remove_pkcs7_padding(plain, cipher.block_size)
    return plain

def load_private_key(path):
    components = load_keys_from_p12(path)   
    return RSA.construct(components)

def load_keys_from_p12(path):
    p12 = crypto.load_pkcs12(open(path, 'rb').read(), b"pass")
    cert = p12.get_certificate()
    pkey = cert.get_pubkey().to_cryptography_key()
    pkey = pkey.public_numbers()
    e, n = pkey.e, pkey.n

    skey = p12.get_privatekey()
    skey = skey.to_cryptography_key()
    skey = skey.private_numbers()
    d = skey.d

    return (n, e, d)


def load_key_from_pem(path):
    return load_pem_private_key(open(path, "rb").read(), password=None, backend=default_backend())

def remove_pkcs7_padding(plain, block_length=8):
    pad_len = plain[-1]
    if pad_len > block_length or pad_len == 0:
        raise Exception("PKCS#7 padding wrong")
    for i in range(1,pad_len+1):
        if plain[-i] != pad_len:
            raise Exception("PKCS#7 padding wrong")
    return plain[:-pad_len]
