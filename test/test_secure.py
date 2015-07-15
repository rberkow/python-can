import unittest

import can
from can.interfaces.interface import Bus
from can.protocols.secure.arbitrationid import ArbitrationID
from can.protocols.secure.securemessage import SecureMessage

can_interface = 'vcan0'
from can.protocols import secure

import logging
logging.getLogger("").setLevel(logging.DEBUG)



class SecureBusTest(unittest.TestCase):

    def testCreateBus(self):
        self.bus = secure.Bus(node_id=0, channel=can_interface)
        self.bus.shutdown()

    def testArbitrationID(self):
        self.arbitration_id = ArbitrationID(priority=5, destination_addresses = [14, 6], source_address=20)
        #check that the number of destinations was correctly set to 2
        self.assertEqual(bin(self.arbitration_id.can_id)[11:13], "10")

    def testMessage(self):
        self.msg = SecureMessage()
        another_msg = SecureMessage(arbitration_id=ArbitrationID(priority=7))
        self.assertTrue(self.msg.check_equality(another_msg, ["priority"]))
