#! /bin/sh
#
# samsung-reset.sh
# Copyright (C) 2021 fabian <fabian@Agrajag>
#
# Distributed under terms of the MIT license.
#

adb shell am force-stop com.samsung.android.email.provider
adb shell am start com.samsung.android.email.provider

monkeyrunner scripts/samsung/request.py
