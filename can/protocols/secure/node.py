import logging

log = logging.getLogger('py1939.node')
log.info('Loading J1939 node')

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
    :param :class:`can.protocols.j1939.NodeName` name:
    :param list(int) address_list:
        A list of potential addresses that this Node will use when claiming
        an address.
    """

    def __init__(self, bus, name):
        self.bus = bus
        self.id_table = IDTable()
        self.node_name = name

    @property
    def address(self):
        return self.known_node_addresses[self.node_name.value]


    def on_message_received(self, msg):


        self.id_table.add_row()

