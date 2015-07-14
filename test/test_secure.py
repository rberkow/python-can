from time import sleep
import unittest
import threading
from sys import version_info

try:
    import queue
except ImportError:
    import Queue as queue
import random


import can
from can.interfaces.interface import Bus
from can.protocols.secure.arbitrationid import ArbitrationID

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
