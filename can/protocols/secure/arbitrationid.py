from can.protocols.j1939.pgn import PGN


class ArbitrationID(object):

    def __init__(self, priority=7, destination_addresses=[], source_address=0):
        """
        Extended ID format (29 bits)
             |---|------|--|------ ------ ------|
               |    |     |   |
        priority    |     |   |
        source address    |   |
        destination quantity  |
        destinations' addresses

        :param int priority:
            Between 0 and 7, where 0 is highest priority.

        :param list destination_addresses:
            Up to 3 ints each between 0 and 63.

        :param int source_address:
            Between 0 and 63.
        """
        self.priority = priority
        self.destination_quantity = len(destination_addresses)
        self.destination_addresses = destination_addresses
        self.source_address = source_address

    @property
    def can_id(self):
        return self.destinations + (self.destination_quantity << 18) + (self.source_address << 20) + (self.priority << 26)

    @can_id.setter
    def can_id(self, value):
        """
        Int between 0 and (2**29) - 1
        """
        self.priority = (value & 0x1C000000) >> 26
        self.source_address = (value & 0x03F00000) >> 20
        self.destination_quantity = (value & 0x000C0000) >> 18
        self.destination_addresses[0] = (value & 0x0003F000) >> 12
        if self.destination_quantity > 1 :
            self.destination_addresses[1] = (value & 0x00000FC0) >> 6
        if self.destination_quantity > 2 :
            self.destination_addresses[2] = (value & 0x0000003F)

    @property
    def destinations(self):
        _destinations = 0x0
        for i, dest in enumerate(self.destination_addresses):
            _destinations += dest << (2 - i) * 6
        return _destinations

    def __str__(self):
        """
        Readable format
        """
        dests = "00" + bin(self.destinations)[2:]
        return "PRI=%d SRC=0x%.2x DST1=0x%.2x DST2=0x%.2x DST3=0x%.2x" % (
                self.priority, self.source_address, int(dests[:6], 2), int(dests[6:12], 2), int(dests[12:], 2))
