#!/bin/bash
#

echo -n "Reverting to snapshot $1_$2... "
virsh --connect qemu:///system snapshot-revert --domain nixos-usenix --snapshotname $1_$2
retVal=$?
if [ $retVal -ne 0 ]; then
    echo "failed"
    exit $retVal
fi
echo "done"

echo -n "Requesting connection... "
echo "ping" | nc -N 192.168.122.57 12345
retVal=$?
if [ $retVal -ne 0 ]; then
    echo "failed"
    exit $retVal
fi
echo "done"
