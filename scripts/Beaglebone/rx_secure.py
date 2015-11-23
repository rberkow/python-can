"""
Script to run from receiving Beaglebone to receive secure CAN messages.
"""

import can
import time
from can.protocols.secure import Bus

interface = 'vcan0'

bus = Bus(channel=interface, claimed_addresses=[0, 2])
print bus.local_node.address
msg = bus.recv(timeout=2)
sum, count = 0, 0
latest_time = 0.0

while(msg is not None):
    if not msg.accepted:
        print "FAKE MESSAGE DETECTED"
    start_time = time.time()
    msg = bus.recv(timeout=2)
    timer = time.time() - start_time
    sum += timer
    count += 1
    latest_time = timer

sum -= timer
if count is not 0:
    print "average receiving time per msg: ", (sum/count)
