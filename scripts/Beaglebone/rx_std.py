"""
Script to run from receiving Beaglebone to receive standard CAN messages.
"""

import can

bus = can.interface.Bus()
with open("rx_msgs.txt", 'w') as f:
	f.write("hello\n")

	msg = bus.recv(timeout=2)
	while(msg is not None):
		print msg
		f.write("{0}\n".format(msg.data[0]))
		msg = bus.recv(timeout=2)
