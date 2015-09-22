"""
Script to run from host computer to control attack/stop attack functions of Hercules board.
"""

import serial

COM_PORT = input("COM port number of Hercules board: ")


ser = serial.Serial(COM_PORT)
ser.baudrate = 19200

if input("Press a key to attack! "):
    ser.write("hackrp:1")

input("Press a key to stop attacking")

ser.write("hackrp:0")

ser.close()
