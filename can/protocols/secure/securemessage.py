import logging
from Crypto.Hash import SHA1
from can import Message

from can.protocols.secure.arbitrationid import ArbitrationID
from can.protocols.secure.constants import pgn_strings, PGN_AC_ADDRESS_CLAIMED
from can.protocols.secure.nodename import NodeName

logger = logging.getLogger(__name__)


class SecureMessage(Message):

    """
    Message object to send
    """

    def __init__(self, timestamp=0.0, arbitration_id=None, data=None, MACs=None, info_strings=None, id_table_entry=None):
        """
        :param float timestamp:
            Bus time in seconds.

        :param :class:`can.protocols.secure.ArbitrationID` arbitration_id:
            Arbitration ID of message (also serves as index for ID Table at receiving node)

        :param bytes/bytearray/list data:
            With length up to 5.

        :param list id_table_entry:
            Metadata about message to add to ID Table of receiving node
        """
        if data is None:
            data = []
        if info_strings is None:
            info_strings = []
        self.timestamp = timestamp
        self.arbitration_id = arbitration_id
        self.data = self._check_data(data)
        self.info_strings = info_strings
        self.id_table_entry = id_table_entry
        self.counter = 0
        self.MACs = []

    def __eq__(self, other):
        """Returns True if the data, source and destinations are the same"""
        if other is None:
            return False
        if self.data != other.data:
            return False
        if self.source != other.source:
            return False
        if self.destintation_quantity != other.destintation_quantity:
            return False
        for i in range(self.destintation_quantity):
            if self.destinations[i] != other.destinations[i]:
                return False
        return True

    @property
    def MACs(self):
        """compute MACs for message"""
        if not data:
            return None
        for i, dest in enumerate(self.destinations):
            self.MACs[i]


    @property
    def destinations(self):
        """Message's destinations' addresses"""
        return self.arbitration_id.destination_addresses

    @property
    def destintation_quantity(self):
        """Number of destinations for the message"""
        return self.arbitration_id.destintation_quantity

    @property
    def source(self):
        """Source address of the message"""
        return self.arbitration_id.source_address

    @property
    def arbitration_id(self):
        return self._arbitration_id

    @arbitration_id.setter
    def arbitration_id(self, other):
        """
        Sets arbitration ID from ArbitrationID object or list of `[priority, destination_addresses, source_address]`
        """
        if other is None:
            self._arbitration_id = ArbitrationID()
        elif not isinstance(other, ArbitrationID):
            self._arbitration_id = ArbitrationID(other)
        else:
            self._arbitration_id = other

    @property
    def id_table_entry(self):
        return self._id_table_entry

    @id_table_entry.setter
    def id_table_entry(self, other):
        """
        Sets values for ID table
        """
        self._id_table_entry = [self.source, self.destintations]


    def _check_data(self, value):
        assert len(value) <= 5, 'Too much data to fit in message. Got {0} bytes'.format(len(value))
        if len(value) > 0:
            assert min(value) >= 0, 'Data values must be between 0 and 255'
            assert max(value) <= 255, 'Data values must be between 0 and 255'
        return value

    def data_segments(self, segment_length=5):
        retval = []
        for i in range(0, len(self.data), segment_length):
            retval.append(self.data[i:i + min(segment_length, (len(self.data) - i))])
        return retval

    def check_equality(self, other, fields, debug=False):
        """
        :param :class:`~can.protocols.secure.SecureMessage` other:
        :param list[str] fields:
        """

        logger.debug("check_equality starting")

        retval = True
        for field in fields:
            try:
                own_value = getattr(self, field)
            except AttributeError:
                logger.warning("'%s' not found in 'self'" % field)
                return False

            try:
                other_value = getattr(other, field)
            except AttributeError:
                logger.debug("'%s' not found in 'other'" % field)
                return False

            if debug:
                self.info_strings.append("%s: %s, %s" % (field, own_value, other_value))
            if own_value != other_value:
                return False

        logger.debug("Messages match")
        return retval

    def __str__(self):
        """

        :return: A string representation of this message.

        """
        # TODO group this into 8 bytes per line and line them up...
        data_string = " ".join("{:02d}".format(byte) for byte in self.data)
        return "{s.timestamp:15.6f}    {s.arbitration_id}    {data}".format(s=self, data=data_string)
