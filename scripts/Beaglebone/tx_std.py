"""
Script to run from transmitting Beaglebone to send standard CAN messages.
"""

import can
import time
from can.message import Message

bus = can.interface.Bus()

for i in range(49, 0, -1):
	msg = Message(data=[i], arbitration_id=0x14240000)
	bus.send(msg)
	time.sleep(1)

