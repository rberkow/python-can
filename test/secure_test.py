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

can_interface = 'vcan0'
from can.protocols import secure

import logging
logging.getLogger("").setLevel(logging.DEBUG)



class SecureBusTest(unittest.TestCase):

    def testCreateBus(self):
        self.bus = secure.Bus(channel=can_interface)
        self.bus.shutdown()
