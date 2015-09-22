"""
Script to run from receiving Beaglebone to receive secure CAN messages.
"""

import can
import time
from can.protocols.secure import Bus

interface = 'can0'

bus = Bus(channel=interface, claimed_addresses=[0, 2])
print bus.local_node.address
with open("rx_msgs.txt", 'w') as f:
    msg = bus.recv(timeout=2)
    while(msg is not None):
        if not msg.accepted:
            print "FAKE MESSAGE DETECTED"
        f.write("{0}\n".format(msg.data[0]))
        msg = bus.recv(timeout=2)
