"""
Script to run from transmitting Beaglebone to send secure CAN messages.
"""


import can
import time
from can.protocols.secure.securemessage import SecureMessage
from can.protocols.secure.arbitrationid import ArbitrationID
from can.protocols.secure import Bus

interface = 'can0'

bus = Bus(channel=interface, claimed_addresses=[0, 1])
print bus.local_node.address
arb = ArbitrationID(priority=5, destination_addresses = [1], source_address=bus.local_node.address)
for i in range(49, 0, -1):
	msg = SecureMessage(data=[i], arbitration_id=arb)
	bus.send(msg)
	time.sleep(1)