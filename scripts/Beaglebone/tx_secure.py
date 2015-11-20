"""
Script to run from transmitting Beaglebone to send secure CAN messages.
"""


import can
import time
from can.protocols.secure.securemessage import SecureMessage
from can.protocols.secure.arbitrationid import ArbitrationID
from can.protocols.secure import Bus

interface = 'vcan0'

bus = Bus(channel=interface, claimed_addresses=[0, 1])
time.clock()
arb = ArbitrationID(priority=5, destination_addresses = [1], source_address=bus.local_node.address)
msg = SecureMessage(data=[50], arbitration_id=arb)
bus.send(msg)
print time.clock()
