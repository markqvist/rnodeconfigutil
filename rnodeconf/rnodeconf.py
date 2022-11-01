#!python3

# MIT License
#
# Copyright (c) 2018-2022 Mark Qvist - unsigned.io/rnode
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from time import sleep
import argparse
import threading
import os
import os.path
import struct
import datetime
import time
import math
from urllib.request import urlretrieve
from importlib import util

program_version = "1.3.0"

def main():
    print("")
    print("This rnodeconf program package is outdated! The rnodeconf utility has been moved into the")
    print("rns package, and the rnodeconf program in this package will no longer be maintained.")
    print("Please uninstall the rnodeconf package, and use rnodeconf from the rns package instead:")
    print("")
    print("   pip uninstall rnodeconf")
    print("")
    print("While installing this version of the rnodeconf package, RNS 0.3.18 should have been")
    print("installed automatically as well. If it did not, you can install it with:")
    print("")
    print("   pip install rns --upgrade")
    print("")
    exit(0)

if __name__ == "__main__":
    main()
