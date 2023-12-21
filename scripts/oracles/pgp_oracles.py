#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2023 Fabian Ising
#
# Distributed under terms of the MIT license.
from mail_generator import MailGenerator
from collections import defaultdict

BOUNDARY = "mixed"
CONTENT_TYPE = "multipart/mixed"

headers = """From: Alice
To: Bob
Subject: PGP test
Content-Type: {content_type}; boundary="{boundary}"
""".format(content_type=CONTENT_TYPE,boundary=BOUNDARY)

part_headers = """--encrypted
Content-Type: application/pgp-encrypted
Content-Disposition: attachment
Content-Transfer-Encoding: 7bit
\r\n"""

part_mime_headers_odd = """Content-Type: application/pgp-encrypted
Content-Disposition: attachment
Content-Transfer-Encoding: 7bit
""".replace("\n", "\r\n")

part_mime_headers_even = """Content-Type: application/octet-stream; name="msg.asc"
Content-Disposition: inline; filename="msg.asc"
Content-Transfer-Encoding: 7bit
""".replace("\n", "\r\n")


footer="""--mixed--"""

template_content = part_headers + """\r\n{content}"""

#template_content = "{content}"

bodystructure = """({content} "mixed" ("boundary" "mixed") NIL NIL NIL)"""

structure_part = '(("application" "pgp-encrypted" NIL NIL NIL "7bit" {message_length} NIL ("attachment" NIL) NIL NIL) ("application" "octet-stream" NIL NIL NIL "7bit" {message_length} NIL ("inline" NIL) NIL NIL) "encrypted" ("boundary" "encrypted" "protocol" "application/pgp-encrypted") NIL NIL NIL)'


class MultipartPGPGenerator(MailGenerator):
    def __init__(self, org, key_file):
        super(MultipartPGPGenerator, self).__init__(org, key_file)
        self.query_counts = defaultdict(int)
        self.mails = {}
        self.next = 1
        self.correct_guesses = set()

    def setup(self, ciphertext_multiplier=1):
        with open("encrypted.pgp", "r") as f:
            self.message = f.read()

    def get_part_size(self):
        return len(self.message)

    def get_footer(self):
        return footer

    def create_mail(self, num, repeat=10, enc_key=None):
        self.mails[num] = Mail(self.message, headers, repeat)
        self.next +=1
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
        return self.mails[num].get_body()

    def get_headers(self, num):
        return self.mails[num].headers

    def get_part_headers(self, num, part):
        return self.mails[num].get_part_headers(part)

    def get_next_unseen(self):
        return self.next

    def generate_mail(self, repeat=10):
        vector_list = []
        for j in range(repeat):
            vector_list.append(self.message)

        return vector_list

class Mail:
    def __init__(self, message, headers, num_parts):
        self.content = message
        self.num_parts = num_parts
        self.headers = headers
        self.body = None # Lazy

    def generate_bodystructure(self):
        all_parts = []
        size = self.get_part_size(1)
        for i in range(0, self.num_parts):
            all_parts.append(structure_part.format(message_length=size))
        return bodystructure.format(content=''.join(all_parts))

    def get_part(self, part):
        print(part, type(part))
        if str(part).endswith("1"):
            return "Version: 1\r\n"
        return self.content

    def get_part_headers(self, part):
        if "." in part:
            part = part.split(".")[-1]
        part = int(part)
        if part % 2 == 0:
            return part_mime_headers_even
        else:
            return part_mime_headers_odd

    def get_part_size(self, part):
        return len(self.content)

    def get_size(self):
        # TODO
        size = self.get_part_size(1) * self.num_parts + len(self.headers)+len(part_headers) * self.num_parts
        return size

    def get_body(self):
        if self.body is None:
            all_parts = []
            for part_num in range(1,self.num_parts+1):
                all_parts.append(template_content.format(content = self.get_part(part_num)))
            self.body = headers + "\r\n".join(all_parts)
        return self.body
