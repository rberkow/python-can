"""
Script to run from transmitting Beaglebone to send standard CAN messages.
"""

import can
import time
from can.message import Message
interface = 'vcan0'
bustype = 'socketcan_ctypes'
bus = can.interface.Bus(channel=interface, bustype=bustype)

NO_OF_MSGS = 100
USEFUL_BITS = 64

sum = 0

for i in range(NO_OF_MSGS - 1, 0, -1):
    start_time = time.time()
    msg = Message(data=[i], arbitration_id=0x14240000)
    bus.send(msg)
    timer = time.time() - start_time
    sum += timer

time_per_msg = sum / NO_OF_MSGS

print "latency: ", time_per_msg
print "throughput: ", USEFUL_BITS / time_per_msg
