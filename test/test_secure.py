import unittest

import can
from can.protocols.secure import Bus
from can.protocols.secure.arbitrationid import ArbitrationID
from can.protocols.secure.securemessage import SecureMessage

can_interface = 'can0'
from can.protocols import secure

import logging
logging.getLogger("").setLevel(logging.DEBUG)



class SecureBusTest(unittest.TestCase):

    # def testCreateBus(self):
    #     self.bus = secure.Bus(channel=can_interface)
    #     self.bus.shutdown()

    # def testArbitrationID(self):
    #     self.arbitration_id = ArbitrationID(priority=5, destination_addresses = [14, 6], source_address=20)
    #     #check that the number of destinations was correctly set to 2
    #     self.assertEqual(bin(self.arbitration_id.can_id)[11:13], "10")

    def testSend(self):
        bus = Bus(channel=can_interface, claimed_addresses=[0, 1])
        print "send addr: {0}".format(bus.local_node.address)
        arb = ArbitrationID(priority=5, destination_addresses = [0], source_address=bus.local_node.address)
        msg = SecureMessage(data=[0, 245, 134], arbitration_id=arb)
        bus.send(msg)

    def testRecv(self):
        bus = Bus(channel=can_interface)
        print "recv addr: {0}".format(bus.local_node.address)
        msg = bus.recv(timeout=2)
        print msg

    # def testMACs(self):
    #     bus = Bus(channel=can_interface, claimed_addresses=[0,1])
    #     msg = SecureMessage(data=[0, 245, 134, 156])
    #     msg.destinations.append(1)
    #     bus.compute_MACs(msg)
    #     node = bus.get_node(1)
    #     node.on_message_received(msg)
    #     self.assertTrue(node.id_table.message_ids)

    def testMessage(self):
        self.msg = SecureMessage()
        another_msg = SecureMessage(arbitration_id=ArbitrationID(priority=7))
        self.assertTrue(self.msg.check_equality(another_msg, ["arbitration_id"]))
