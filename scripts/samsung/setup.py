#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2021 Fabian Ising
#
# Distributed under terms of the MIT license.

"""

"""
from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice
import sys

package = "com.samsung.android.email.provider"
device = MonkeyRunner.waitForConnection()
print("Uninstalling email")
device.removePackage(package)
print("Installing email")
installed = device.installPackage("/mnt/SharedFolder/Samsung Email_v6.1.12.1_apkpure.com.apk")
print("Install done. Result: " + str(installed))

device.shell("am force-stop com.samsung.android.email.provider")
#print(device.startActivity(component="com.google.android.gm.lite/com.google.android.gm.ConversationListActivityGmail"))
activity = "com.samsung.android.email.ui.settings.setup.login.LoginActivity"
runComponent = package + "/" + activity
device.startActivity(component=runComponent)
device.type("samsungsetup@example.org")
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.type("samsung")
print("Selecting manual setup")
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_ENTER", MonkeyDevice.DOWN_AND_UP)
#MonkeyRunner.sleep(2)
# Select IMAP
print("Selecting IMAP")
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_ENTER", MonkeyDevice.DOWN_AND_UP)

print("Waiting for next activity ...")
MonkeyRunner.sleep(3.0)
# Go to IMAP server
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)


print("Setting IMAP server")
# Clear field
for i in range(20):
    device.press("KEYCODE_DEL", device.DOWN_AND_UP)

device.type(sys.argv[1])

#GO to security setting
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_ENTER", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_ENTER", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_ENTER", MonkeyDevice.DOWN_AND_UP)

print("Setting SMTP server")
# Enter SMTP
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)


# Clear field
for i in range(20):
    device.press("KEYCODE_DEL", device.DOWN_AND_UP)

device.type(sys.argv[1])

#GO to security setting
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_ENTER", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_ENTER", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_ENTER", MonkeyDevice.DOWN_AND_UP)


# Go to sign in
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_TAB", MonkeyDevice.DOWN_AND_UP)
device.press("KEYCODE_ENTER", MonkeyDevice.DOWN_AND_UP)

print("Waiting for completed sign in")
MonkeyRunner.sleep(15.0)
device.shell("am force-stop com.samsung.android.email.provider")
activity = "com.samsung.android.email.composer.activity.MessageCompose"
runComponent = package + "/" + activity
device.startActivity(component=runComponent)

# Allow permissions
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_ENTER", device.DOWN_AND_UP)
device.press("KEYCODE_ENTER", device.DOWN_AND_UP)
# To
device.type("test@example.org")
# Subject
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.type("SENT")
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_ENTER", device.DOWN_AND_UP)

MonkeyRunner.sleep(10.0)
device.shell("am force-stop com.samsung.android.email.provider")

activity = "com.samsung.android.email.composer.activity.MessageCompose"
runComponent = package + "/" + activity
device.startActivity(component=runComponent)

# To
device.type("test@example.org")
# Subject
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.type("SENT")
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_ENTER", device.DOWN_AND_UP)
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_TAB", device.DOWN_AND_UP)
device.press("KEYCODE_ENTER", device.DOWN_AND_UP)
