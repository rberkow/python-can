"""
python-can requires the setuptools package to be installed.
"""
from setuptools import setup

__version__ = 1.1

# TODO
# This dict will be updated as we try to select the best option during
# the build process. However, values in setup.cfg will be used, if
# defined.
rc = {'backend': 'socketcan'}

setup(
    name="python-can",
    url="https://bitbucket.org/hardbyte/python-can",
    version=__version__,
    packages=['can'],
    author="Brian Thorne",
    author_email="bthorne@dynamiccontrols.com",
    description="Controller Area Network interface module for Python",
    license="LGPL v3",
    
    package_data={
        "": ["CONTRIBUTORS.txt", "LICENSE.txt"],
        "doc": ["*.*"]
        },

    scripts=["./bin/can_logger.py", "./bin/can_printer.py"],
    )
