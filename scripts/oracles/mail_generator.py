#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2023 Fabian Ising; Tobias Kappert
#
# Distributed under terms of the MIT license.

"""

"""
class MailGenerator(object):
    def __init__(self, org, key_file=None):
        self.org = org
        if key_file is not None:
            import smime_lib as smime
            self.priv_key = smime.load_key_from_pem(key_file)
            self.n = self.priv_key.private_numbers().public_numbers.n
            self.enc = self.priv_key.private_numbers().public_numbers.e
            self.dec = self.priv_key.private_numbers().d

    def get_headers(self):
        return headers

    def get_footer(self):
        return footer

    def setup(self):
        pass

    def create_mail(self, uid):
        pass

class BlockDecryptedException(Exception):
    pass
