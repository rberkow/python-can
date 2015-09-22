class IDTable(object):

    def __init__(self):
        self.message_ids = []

    def __str__(self):
        return str(self.message_ids)

    def add_row(self, sender_id, destination_ids):
        self.message_ids.append({'sender': sender_id, 
                                 'destination': destination_ids,
                                 'count': 1})

    def increment(self, sender_id, destination_ids):
        if self.get_entry(sender_id, destination_ids):
            self.get_entry(sender_id, destination_ids)['count'] += 1
        else:
            self.add_row(sender_id, destination_ids)

        return self.get_count(sender_id, destination_ids)

    def get_count(self, sender_id, destination_ids):
        return self.get_entry(sender_id, destination_ids)['count']

    def get_entry(self, sender_id, destination_ids):
        retval = {}
        for entry in self.message_ids:
            if (entry['sender'] == sender_id) and (entry['destination'] == destination_ids):
                retval = entry
        return retval

    def set_count(self, sender_id, destination_ids, value):
        if self.get_entry(sender_id, destination_ids):
            self.get_entry(sender_id, destination_ids)['count'] = value
        else:
            self.add_row(sender_id, destination_ids)

        return self.get_count(sender_id, destination_ids)
