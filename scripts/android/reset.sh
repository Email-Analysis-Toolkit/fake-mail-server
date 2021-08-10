#!/bin/bash
#

# Reset SUT
expect scripts/android/reset.expect $1_$2

# Request Connection
sleep 2 && adb shell svc wifi disable
monkeyrunner scripts/android/monkey_swipe.py
