"""
Implementing cyber-security for CAN protocol. Referring to protocol described in [1].
[1] C. Lin and A. Sangiovanni-Vincentelli, 'Cyber-Security for the Controller Area Network (CAN) Communication Protocol', 
in International Conference on Cyber Security, Cyber Warfare and Digital Forensic (CyberSec), Kuala Lumpur, Malaysia, 2012, pp. 1-7.

"""

import logging
import string
import random
import select
import ctypes
import can

from Crypto.Hash import HMAC
# By this stage the can.rc should have been set up
from can.message import Message as RawMessage
from can.interfaces.interface import Bus as RawCanBus
from can.interfaces.socketcan_ctypes import *
from can.interfaces.socketcan_constants import *
from can.bus import BusABC

# Import our new message type
from can.protocols.secure.securemessage import SecureMessage
from can.protocols.secure.node import Node


logger = logging.getLogger(__name__)


class Bus(BusABC):

    """
    A CAN Bus that implements the Chung-Wei Lin security features. Only works with SocketCAN for now.

    :param int node_id:
        An integer indicating the node ID. Messages must be directed to this node 
        in order to be accepted at this instance of the bus.

    """

    channel_info = "secure bus"

    def __init__(self,
                 channel=can.rc['channel'],
                 receive_own_messages=False,
                 claimed_addresses=[],
                 *args, **kwargs):
        """
        :param str channel:
            The can interface name with which to create this bus. An example channel
            would be 'vcan0'.
        :param list claimed_addresses:
            Addresses of nodes that have been instantiated already elsewhere on the bus.
        """

        self.socket = createSocket()

        logging.debug("Result of createSocket was %d", self.socket)
        error = bindSocket(self.socket, channel)

        logging.debug("bindSocket returned %d", error)

        self.nodes = []

        for addr in claimed_addresses:
            self.nodes.append(Node(bus=self, address=addr))

        self.nodes.append(self.local_node)



        if receive_own_messages:
            error1 = recv_own_msgs(self.socket)

        super(Bus, self).__init__(*args, **kwargs)

    @property
    def local_node(self):
        retval = 0
        while retval in self.node_addresses:
            retval += 1
        else:
            return Node(bus=self, address=retval)

    @property
    def node_addresses(self):
        retval = []
        for node in self.nodes:
            retval.append(node.address)
        return retval

    def recv(self, timeout=None):
        log.debug("Trying to read a msg")

        if timeout is None or len(select.select([self.socket],
                                                [], [], timeout)[0]) > 0:
            packet = capturePacket(self.socket)
        else:
            # socket wasn't readable or timeout occurred
            return None

        log.debug("Receiving a message")

        arbitration_id = packet['CAN ID'] & MSK_ARBID

        # Flags: EXT, RTR, ERR
        flags = (packet['CAN ID'] & MSK_FLAGS) >> 29

        rx_msg = SecureMessage(
            timestamp=packet['Timestamp'],
            arbitration_id=arbitration_id,
            dlc=packet['DLC'],
            data=packet['Data'],
            MACs=packet['MAC']
        )

        for dest in rx_msg.destinations:
            if dest not in self.nodes:
                self.nodes.append(Node(bus=self, address=dest))

        self.local_node.on_message_received(rx_msg)

        return rx_msg

    def send(self, msg):
        self.compute_MACs(msg)
        sendPacket(self.socket, msg)
        return None

    def get_node(self, address):
        for n in self.nodes:
            if n.address == address:
                return n
        return None

    def compute_MACs(self, msg):
        """compute MACs for message"""
        for dest in msg.destinations:
            node = self.get_node(dest)
            msg.MACs.append(HMAC.new(b''+node.key.hexdigest(), msg.binary_data_string))

def _build_can_frame(message):
    log.debug("Packing a can frame")
    arbitration_id = message.arbitration_id.can_id | 0x80000000
    log.debug("Data: %s", message.data)
    log.debug("Type: %s", type(message.data))
    log.debug("MAC: %s", [int(mac.hexdigest(), 16) for mac in message.MACs])

    # TODO need to understand the extended frame format
    frame = CAN_FRAME_MAC()
    frame.can_id = arbitration_id
    frame.can_dlc = len(message.data)
    frame.MAC[:len(message.destinations)] = [int(mac.hexdigest(), 16) for mac in message.MACs]

    frame.data[:frame.can_dlc] = message.data

    logging.debug("sizeof frame: %d", ctypes.sizeof(frame))
    log.debug("MACs: %s", frame.MAC)
    return frame


def sendPacket(socket, message):
    frame = _build_can_frame(message)
    bytes_sent = libc.write(socket, ctypes.byref(frame), ctypes.sizeof(frame))
    if bytes_sent == -1:
        logging.debug("Error sending frame")

    return bytes_sent

def capturePacket(socketID):
    """
    Captures a packet of data from the given socket.

    :param int socketID:
        The socket to read from

    :return:
        A dictionary with the following keys:
        +-----------+----------------------------+
        | 'CAN ID'  |  int                       |
        +-----------+----------------------------+
        | 'DLC'     |  int                       |
        +-----------+----------------------------+
        | 'Data'    |  list                      |
        +-----------+----------------------------+
        | 'MAC'     |  int                       |
        +-----------+----------------------------+
        |'Timestamp'|   float                    |
        +-----------+----------------------------+

    """
    packet = {}

    frame = CAN_FRAME_MAC()
    time = TIME_VALUE()

    # Fetching the Arb ID, DLC and Data
    bytes_read = libc.read(socketID, ctypes.byref(frame), ctypes.sizeof(frame))

    # Fetching the timestamp
    error = libc.ioctl(socketID, SIOCGSTAMP, ctypes.byref(time))

    packet['CAN ID'] = frame.can_id
    packet['DLC'] = frame.can_dlc
    packet["Data"] = [frame.data[i] for i in range(frame.can_dlc)]
    packet['MAC'] = [frame.MAC[i] for i in range(3)]

    timestamp = time.tv_sec + (time.tv_usec / 1000000.0)

    packet['Timestamp'] = timestamp

    return packet


class CAN_FRAME_MAC(ctypes.Structure):
    # See /usr/include/linux/can.h for original struct
    # The 32bit can id is directly followed by the 8bit data link count
    # The data field is aligned on an 8 byte boundary, hence the padding.
    # Aligns the data field to an 8 byte boundary
    _fields_ = [("can_id", ctypes.c_uint32),
                ("can_dlc", ctypes.c_uint8),
                ("padding", ctypes.c_ubyte * 3),
                ("data", ctypes.c_uint8 * 8),
                ("MAC",  ctypes.c_uint32 * 3)
                ]