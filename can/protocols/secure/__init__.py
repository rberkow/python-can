"""
Implementing cyber-security for CAN protocol. Referring to protocol described in [1].
[1] C. Lin and A. Sangiovanni-Vincentelli, 'Cyber-Security for the Controller Area Network (CAN) Communication Protocol', 
in International Conference on Cyber Security, Cyber Warfare and Digital Forensic (CyberSec), Kuala Lumpur, Malaysia, 2012, pp. 1-7.

"""

import logging
import select
import ctypes
import can


# By this stage the can.rc should have been set up
from can.message import Message as RawMessage
from can.interfaces.interface import Bus as RawCanBus
from can.interfaces.socketcan_ctypes import *
from can.interfaces.socketcan_constants import *
from can.interfaces import interface

from can.notifier import Notifier

# Import our new message type
from can.protocols.secure.securemessage import SecureMessage
from can.protocols.secure.pgn import PGN
from can.bus import BusABC
from can.protocols.secure.node import Node
from can.protocols.secure.nodename import NodeName
from can.protocols.secure.arbitrationid import ArbitrationID


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
                 *args, **kwargs):
        """
        :param str channel:
            The can interface name with which to create this bus. An example channel
            would be 'vcan0'.
        """

        self.socket = createSocket()

        log.debug("Result of createSocket was %d", self.socket)
        error = bindSocket(self.socket, channel)

        if receive_own_messages:
            error1 = recv_own_msgs(self.socket)

        super(Bus, self).__init__(*args, **kwargs)

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
            is_remote_frame=bool(flags & SKT_RTRFLG),
            extended_id=bool(flags & EXTFLG),
            is_error_frame=bool(flags & SKT_ERRFLG),
            arbitration_id=arbitration_id,
            dlc=packet['DLC'],
            data=packet['Data'],
            MACs=packet['MAC']
        )

        return rx_msg

    def send(self, msg):
        return None

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

    frame = CAN_FRAME()
    time = TIME_VALUE()

    # Fetching the Arb ID, DLC and Data
    bytes_read = libc.read(socketID, ctypes.byref(frame), ctypes.sizeof(frame))

    # Fetching the timestamp
    error = libc.ioctl(socketID, SIOCGSTAMP, ctypes.byref(time))

    packet['CAN ID'] = frame.can_id
    packet['DLC'] = frame.can_dlc
    packet["Data"] = [frame.data[i] for i in range(frame.can_dlc)]
    packet['MAC'] = frame.MAC

    timestamp = time.tv_sec + (time.tv_usec / 1000000.0)

    packet['Timestamp'] = timestamp

    return packet

class CAN_FRAME(ctypes.Structure):
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