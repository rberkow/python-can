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
import os

from Crypto.Hash import HMAC
# By this stage the can.rc should have been set up
from can.message import Message as RawMessage
from can.interfaces.interface import Bus as RawCanBus
from can.interfaces.socketcan_ctypes import *
from can.interfaces.socketcan_constants import *
from can.bus import BusABC

# Import our new message type
from can.protocols.secure.securemessage import SecureMessage
from can.protocols.secure.arbitrationid import ArbitrationID
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
                 fd_frames=False,
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

        if fd_frames:
            set_fd_frames(self.socket)

        logging.debug("Result of createSocket was %d", self.socket)
        error = bindSocket(self.socket, channel)

        logging.debug("bindSocket returned %d", error)

        self.nodes = []

        for addr in claimed_addresses:
            self.nodes.append(Node(bus=self, address=addr))

        self.local_node = self.find_local_node

        self.nodes.append(self.local_node)

        if receive_own_messages:
            error1 = recv_own_msgs(self.socket)

        super(Bus, self).__init__(*args, **kwargs)

    @property
    def find_local_node(self):
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

        arbitration_id = ArbitrationID()
        arbitration_id.can_id = packet['CAN ID']

        # Flags: EXT, RTR, ERR
        flags = (packet['CAN ID'] & MSK_FLAGS) >> 29

        rx_msg = SecureMessage(
            timestamp=packet['Timestamp'],
            arbitration_id=arbitration_id,
            data=packet['Data'][:-2],
            MACs=packet['Data'][-2:]
        )

        for dest in rx_msg.destinations:
            if dest not in self.nodes:
                self.nodes.append(Node(bus=self, address=dest))

        self.local_node.on_message_received(rx_msg)

        log.debug("Local node address at receiver: %x", self.local_node.address)

        log.debug("arbID at receiver: %s", rx_msg.arbitration_id)

        log.debug("ID table entry: %s", self.local_node.id_table)

        return rx_msg

    def send(self, msg):
        self.compute_MACs(msg)
        msg.arbitration_id.source_address = self.local_node.address
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
            if not self.get_node(dest):
                self.nodes.append(Node(bus=self, address=dest))
            node = self.get_node(dest)
            msg.MACs.append(HMAC.new(b''+node.key.hexdigest(), msg.binary_data_string))

def _build_can_frame(message):
    log.debug("Packing a can frame")
    message.data += [0] * (6 - len(message.data))


    macs = hex_MAC(message)[-2:]

    data_to_pack = [d for d in message.data] + [int(byte, 16) for byte in macs]

    if len(data_to_pack) < 9:
        frame = CAN_FRAME()
        frame.can_dlc = len(data_to_pack)
        frame.__res0 = 0;
        frame.__res1 = 0;
    else:
        frame = CANFD_FRAME()
        frame.len = 15

    frame.can_id = message.arbitration_id.can_id | 0x80000000


    frame.data[:len(data_to_pack)] = bytearray(data_to_pack)
    log.debug("arbID at sender: %s", message.arbitration_id)
    return frame

def hex_MAC(message):
    retval = []
    for mac in message.MACs:
        bytes = []
        string_mac = str(mac.hexdigest())
        for i in range(0, len(string_mac)-1, 2):
            bytes.append(string_mac[i: i+2])
        retval+=bytes
    return retval


def set_fd_frames(socket_id):
    setting = ctypes.c_int(1);
    error = libc.setsockopt(socket_id, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, ctypes.byref(setting), ctypes.sizeof(setting))

    if error < 0:
        log.error("Couldn't enable FD frames")

def sendPacket(socket, message):
    frame = _build_can_frame(message)
    bytes_sent = libc.write(socket, ctypes.byref(frame), ctypes.sizeof(frame))
    log.debug("%d bytes sent", bytes_sent)
    if bytes_sent == -1:
        libc.perror("Error sending frame")

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
        | 'Data'    |  list                      |
        +-----------+----------------------------+
        |'Timestamp'|   float                    |
        +-----------+----------------------------+

    """
    packet = {}

    frame = CAN_FRAME()
    time = TIME_VALUE()



    # Fetching the Arb ID, DLC and Data
    bytes_read = libc.read(socketID, ctypes.byref(frame), ctypes.sizeof(frame))

    log.debug("%d bytes read", bytes_read)

    # Fetching the timestamp
    error = libc.ioctl(socketID, SIOCGSTAMP, ctypes.byref(time))

    packet['CAN ID'] = frame.can_id
    packet['Length'] = frame.can_dlc
    packet['Data'] = frame.data[:8]

    timestamp = time.tv_sec + (time.tv_usec / 1000000.0)

    packet['Timestamp'] = timestamp

    return packet


class CANFD_FRAME(ctypes.Structure):
    # See /usr/include/linux/can.h for original struct
    # The 32bit can id is directly followed by the 8bit data link count
    # The data field is aligned on an 8 byte boundary, hence the padding.
    # Aligns the data field to an 8 byte boundary
    _fields_ = [("can_id", ctypes.c_uint32),
                ("len", ctypes.c_uint8),
                ("flags", ctypes.c_uint8),
                ("res0", ctypes.c_uint8),
                ("res1", ctypes.c_uint8),
                ("data", ctypes.c_uint8 * 64)
                ]