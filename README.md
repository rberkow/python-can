The **C**ontroller **A**rea **N**etwork is a bus standard designed to 
allow microcontrollers and devices to communicate with each other. It 
has priority based bus arbitration, reliable deterministic 
communication. It is used in cars, trucks, wheelchairs... [wikipedia][1] 
has more info.

# python-can

## Installation

A Controller Area Networking interface is required for `python-can` to do
anything useful. The two primary interfaces are `socketcan` on GNU/Linux 
and [Kvaser][1]'s CANLib SDK for Windows (also available on Linux).

The default interface can be selected at install time with a configuration
script. Alternatively, before creating a **bus** object call `can.use`.

### GNU/Linux dependencies

Reasonably modern Linux Kernels (2.6.25 or newer) have an implementation of 
``socketcan``. This version of python-can will directly use socketcan
if Python 3.3 or greater is installed, otherwise that interface is 
used via ctypes.

### Windows dependencies

To install `python-can` using the Kvaser CANLib SDK as the backend:

1. Install the [latest stable release of Python][4].

2. Install [Kvaser's latest Windows CANLib drivers][5].

3. Test that Kvaser's own tools work to ensure the driver is properly 
installed and that the hardware is working.


## Install python-can

Two options, install normally with:

    ``python setup.py install``

Or to do a "development" install of this package to your machine (this allows 
you to make changes locally or pull updates from the Mercurial repository and
use them without having to reinstall):

    python setup.py develop

On linux you will probably need sudo rights. 


## Generating Documentation

The documentation for python-can has been generated with Sphinx. 

With sphinx installed the documentation can be generated with

    ``python setup.py build_sphinx``
    
    
[1]: http://en.wikipedia.org/wiki/CAN_bus
[2]: http://www.kvaser.com
[3]: http://www.brownhat.org/docs/socketcan/llcf-api.html
[4]: http://python.org/download/
[5]: http://www.kvaser.com/en/downloads.html
