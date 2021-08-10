#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2021 fabian <fabian@Agrajag>
#
# Distributed under terms of the MIT license.

from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice

device = MonkeyRunner.waitForConnection()

print("Swiping down")
device.drag((300, 500), (300,1600), 0.5, 5)
