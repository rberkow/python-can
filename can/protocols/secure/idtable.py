class IDTable(object):

    def __init__(self):
        self.message_ids = []

    def __str__(self):
    	return str(self.message_ids)

    def add_row(self, sender_id, destination_ids):
    	self.message_ids.append({'sender': sender_id, 
    							 'destination': destination_ids})

