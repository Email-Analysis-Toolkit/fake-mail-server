#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2023 Fabian Ising
#
# Distributed under terms of the MIT license.

"""

"""
from imaplib import IMAP4
import sys
import smime_lib as smime

with open("smime_key.pem") as pem:
    smime_key = pem.read()

with IMAP4("localhost") as I:
    I.login("oracle", "oracle")
    I.select()
    count = 0
    downloaded = set()
    while True:
        typ, data = I.uid('search', None, "ALL")
        for num in data[0].split():
            if num not in downloaded:
                typ, data = I.uid('fetch', num, 'BODY.PEEK[1]')
                if b'\n\n' in smime.decrypt(data[0][1]):
                    print(f"Downloading all parts of {num}")
                    for i in range(2, 101):
                        typ, data = I.uid('fetch', num, f'BODY.PEEK[{i}]')
            downloaded.add(num)
