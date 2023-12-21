#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2021 Fabian Ising
#
# Distributed under terms of the MIT license.

import applescript
import sys

def reset():
    applescript.tell.app("Mail", "quit")

def refresh():
    print(applescript.tell.app("Finder", "open application file id \"com.apple.mail\"").err)
    applescript.tell.app("Mail", "check for new mail in 'Monitor'")

def main():
    if sys.argv[1] == "reset":
        reset()
    elif sys.argv[1] == "refresh":
        refresh()

if __name__ == "__main__":
    main()
