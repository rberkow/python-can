import logging

log = logging.getLogger('secure.node')
log.info('Loading secure node')

from Crypto.Hash import SHA1
from Crypto.Hash import HMAC

from can import Listener, CanError
from can.protocols.secure.constants import *
from can.protocols.secure.idtable import IDTable
from can.protocols.secure.nodename import NodeName


class DuplicateTransmissionError(CanError):
    pass


class InaccessibleDestinationError(CanError):
    pass


class Node(Listener):

    """
    :param :class:`can.Bus` bus:
        Bus that the node is on
    :param int address:
        Address of the node
    """

    def __init__(self, bus, address):
        self.bus = bus
        self.id_table = IDTable()
        self.address = address
        self.key = self.generate_key()

    def generate_key(self):
        """
        This should be randomly generated, but I don't have time to implement key exchange;
        it is simply be a hash of the address for now.
        """
        addr = str(self.address)
        h = SHA1.new()
        h.update(b''+addr)
        return h
        
    def on_message_received(self, msg):
        print msg.MACs
        m = msg.MACs[:2]
        m = [str(hex(x)) for x in m]
        string_mac = ""
        for x in m:
            string_mac += x[-2:]
        h = HMAC.new(b''+self.key.hexdigest(), msg.binary_data_string).hexdigest()[-4:]
        log.debug("MACs at receiving node: %s", string_mac)
        log.debug("MACs computed at node: %s", h)
        if string_mac == h:
            log.debug("source: %d, destination: %d", msg.source, msg.destinations[0])
            self.id_table.add_row(msg.source, msg.destinations)
