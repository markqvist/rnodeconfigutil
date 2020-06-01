#!python3

# MIT License
#
# Copyright (c) 2018 Mark Qvist - unsigned.io
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

rnode = None
rnode_serial = None
rnode_baudrate = 115200
known_keys = [["unsigned.io", "30819f300d06092a864886f70d010101050003818d0030818902818100e5d46084e445595376bf7efd9c6ccf19d39abbc59afdb763207e4ff68b8d00ebffb63847aa2fe6dd10783d3ea63b55ac66f71ad885c20e223709f0d51ed5c6c0d0b093be9e1d165bb8a483a548b67a3f7a1e4580f50e75b306593fa6067ae259d3e297717bd7ff8c8f5b07f2bed89929a9a0321026cf3699524db98e2d18fb2d020300ff39"]]
ranges = { 0xA4: [410000000, 525000000, 14], 0xA9: [820000000, 1020000000, 17] }
firmware_update_url = "https://github.com/markqvist/RNode_Firmware/raw/master/Precompiled/rnode_firmware_latest.hex"

class RNS():
    @staticmethod
    def log(msg):
        logtimefmt   = "%Y-%m-%d %H:%M:%S"
        timestamp = time.time()
        logstring = "["+time.strftime(logtimefmt)+"] "+msg
        print(logstring)

    @staticmethod
    def hexrep(data, delimit=True):
        delimiter = ":"
        if not delimit:
            delimiter = ""
        hexrep = delimiter.join("{:02x}".format(c) for c in data)
        return hexrep

    @staticmethod
    def prettyhexrep(data):
        delimiter = ""
        hexrep = "<"+delimiter.join("{:02x}".format(c) for c in data)+">"
        return hexrep

class KISS():
    FEND            = 0xC0
    FESC            = 0xDB
    TFEND           = 0xDC
    TFESC           = 0xDD
    
    CMD_UNKNOWN     = 0xFE
    CMD_DATA        = 0x00
    CMD_FREQUENCY   = 0x01
    CMD_BANDWIDTH   = 0x02
    CMD_TXPOWER     = 0x03
    CMD_SF          = 0x04
    CMD_CR          = 0x05
    CMD_RADIO_STATE = 0x06
    CMD_RADIO_LOCK  = 0x07
    CMD_DETECT      = 0x08
    CMD_READY       = 0x0F
    CMD_STAT_RX     = 0x21
    CMD_STAT_TX     = 0x22
    CMD_STAT_RSSI   = 0x23
    CMD_STAT_SNR    = 0x24
    CMD_BLINK       = 0x30
    CMD_RANDOM      = 0x40
    CMD_FW_VERSION  = 0x50
    CMD_ROM_READ    = 0x51
    CMD_ROM_WRITE   = 0x52
    CMD_ROM_WIPE    = 0x59
    CMD_CONF_SAVE   = 0x53
    CMD_CONF_DELETE = 0x54

    DETECT_REQ      = 0x73
    DETECT_RESP     = 0x46
    
    RADIO_STATE_OFF = 0x00
    RADIO_STATE_ON  = 0x01
    RADIO_STATE_ASK = 0xFF
    
    CMD_ERROR           = 0x90
    ERROR_INITRADIO     = 0x01
    ERROR_TXFAILED      = 0x02
    ERROR_EEPROM_LOCKED = 0x03

    @staticmethod
    def escape(data):
        data = data.replace(bytes([0xdb]), bytes([0xdb, 0xdd]))
        data = data.replace(bytes([0xc0]), bytes([0xdb, 0xdc]))
        return data

class ROM():
    PRODUCT_RNODE  = 0x03
    MODEL_A4       = 0xA4
    MODEL_A9       = 0xA9

    ADDR_PRODUCT   = 0x00
    ADDR_MODEL     = 0x01
    ADDR_HW_REV    = 0x02
    ADDR_SERIAL    = 0x03
    ADDR_MADE      = 0x07
    ADDR_CHKSUM    = 0x0B
    ADDR_SIGNATURE = 0x1B
    ADDR_INFO_LOCK = 0x9B
    ADDR_CONF_SF   = 0x9C
    ADDR_CONF_CR   = 0x9D
    ADDR_CONF_TXP  = 0x9E
    ADDR_CONF_BW   = 0x9F
    ADDR_CONF_FREQ = 0xA3
    ADDR_CONF_OK   = 0xA7

    INFO_LOCK_BYTE = 0x73
    CONF_OK_BYTE   = 0x73

class RNode():
    def __init__(self, serial_instance):
        self.serial = serial_instance
        self.timeout     = 100

        self.r_frequency = None
        self.r_bandwidth = None
        self.r_txpower   = None
        self.r_sf        = None
        self.r_state     = None
        self.r_lock      = None

        self.sf = None
        self.cr = None
        self.txpower = None
        self.frequency = None
        self.bandwidth = None

        self.detected = None

        self.eeprom = None
        self.major_version = None
        self.minor_version = None
        self.version = None

        self.provisioned = None
        self.product = None
        self.model = None
        self.hw_rev = None
        self.made = None
        self.serialno = None
        self.checksum = None
        self.signature = None
        self.signature_valid = False
        self.vendor = None

        self.min_freq = None
        self.max_freq = None
        self.max_output = None

        self.configured = None
        self.conf_sf = None
        self.conf_cr = None
        self.conf_txpower = None
        self.conf_frequency = None
        self.conf_bandwidth = None

    def readLoop(self):
        try:
            in_frame = False
            escape = False
            command = KISS.CMD_UNKNOWN
            data_buffer = b""
            command_buffer = b""
            last_read_ms = int(time.time()*1000)

            while self.serial.is_open:
                if self.serial.in_waiting:
                    byte = ord(self.serial.read(1))
                    last_read_ms = int(time.time()*1000)

                    if (in_frame and byte == KISS.FEND and command == KISS.CMD_ROM_READ):
                        self.eeprom = data_buffer
                        in_frame = False
                        data_buffer = b""
                        command_buffer = b""
                    elif (byte == KISS.FEND):
                        in_frame = True
                        command = KISS.CMD_UNKNOWN
                        data_buffer = b""
                        command_buffer = b""
                    elif (in_frame and len(data_buffer) < 512):
                        if (len(data_buffer) == 0 and command == KISS.CMD_UNKNOWN):
                            command = byte
                        elif (command == KISS.CMD_ROM_READ):
                            if (byte == KISS.FESC):
                                escape = True
                            else:
                                if (escape):
                                    if (byte == KISS.TFEND):
                                        byte = KISS.FEND
                                    if (byte == KISS.TFESC):
                                        byte = KISS.FESC
                                    escape = False
                                data_buffer = data_buffer+bytes([byte])
                        elif (command == KISS.CMD_DATA):
                            if (byte == KISS.FESC):
                                escape = True
                            else:
                                if (escape):
                                    if (byte == KISS.TFEND):
                                        byte = KISS.FEND
                                    if (byte == KISS.TFESC):
                                        byte = KISS.FESC
                                    escape = False
                                data_buffer = data_buffer+bytes([byte])
                        elif (command == KISS.CMD_FREQUENCY):
                            if (byte == KISS.FESC):
                                escape = True
                            else:
                                if (escape):
                                    if (byte == KISS.TFEND):
                                        byte = KISS.FEND
                                    if (byte == KISS.TFESC):
                                        byte = KISS.FESC
                                    escape = False
                                command_buffer = command_buffer+bytes([byte])
                                if (len(command_buffer) == 4):
                                    self.r_frequency = command_buffer[0] << 24 | command_buffer[1] << 16 | command_buffer[2] << 8 | command_buffer[3]
                                    RNS.log("Radio reporting frequency is "+str(self.r_frequency/1000000.0)+" MHz")
                                    self.updateBitrate()

                        elif (command == KISS.CMD_BANDWIDTH):
                            if (byte == KISS.FESC):
                                escape = True
                            else:
                                if (escape):
                                    if (byte == KISS.TFEND):
                                        byte = KISS.FEND
                                    if (byte == KISS.TFESC):
                                        byte = KISS.FESC
                                    escape = False
                                command_buffer = command_buffer+bytes([byte])
                                if (len(command_buffer) == 4):
                                    self.r_bandwidth = command_buffer[0] << 24 | command_buffer[1] << 16 | command_buffer[2] << 8 | command_buffer[3]
                                    RNS.log("Radio reporting bandwidth is "+str(self.r_bandwidth/1000.0)+" KHz")
                                    self.updateBitrate()

                        elif (command == KISS.CMD_FW_VERSION):
                            if (byte == KISS.FESC):
                                escape = True
                            else:
                                if (escape):
                                    if (byte == KISS.TFEND):
                                        byte = KISS.FEND
                                    if (byte == KISS.TFESC):
                                        byte = KISS.FESC
                                    escape = False
                                command_buffer = command_buffer+bytes([byte])
                                if (len(command_buffer) == 2):
                                    self.major_version = command_buffer[0]
                                    self.minor_version = command_buffer[1]
                                    self.updateVersion()

                        elif (command == KISS.CMD_TXPOWER):
                            self.r_txpower = byte
                            RNS.log("Radio reporting TX power is "+str(self.r_txpower)+" dBm")
                        elif (command == KISS.CMD_SF):
                            self.r_sf = byte
                            RNS.log("Radio reporting spreading factor is "+str(self.r_sf))
                            self.updateBitrate()
                        elif (command == KISS.CMD_CR):
                            self.r_cr = byte
                            RNS.log("Radio reporting coding rate is "+str(self.r_cr))
                            self.updateBitrate()
                        elif (command == KISS.CMD_RADIO_STATE):
                            self.r_state = byte
                        elif (command == KISS.CMD_RADIO_LOCK):
                            self.r_lock = byte
                        elif (command == KISS.CMD_STAT_RX):
                            if (byte == KISS.FESC):
                                escape = True
                            else:
                                if (escape):
                                    if (byte == KISS.TFEND):
                                        byte = KISS.FEND
                                    if (byte == KISS.TFESC):
                                        byte = KISS.FESC
                                    escape = False
                                command_buffer = command_buffer+bytes([byte])
                                if (len(command_buffer) == 4):
                                    self.r_stat_rx = ord(command_buffer[0]) << 24 | ord(command_buffer[1]) << 16 | ord(command_buffer[2]) << 8 | ord(command_buffer[3])

                        elif (command == KISS.CMD_STAT_TX):
                            if (byte == KISS.FESC):
                                escape = True
                            else:
                                if (escape):
                                    if (byte == KISS.TFEND):
                                        byte = KISS.FEND
                                    if (byte == KISS.TFESC):
                                        byte = KISS.FESC
                                    escape = False
                                command_buffer = command_buffer+bytes([byte])
                                if (len(command_buffer) == 4):
                                    self.r_stat_tx = ord(command_buffer[0]) << 24 | ord(command_buffer[1]) << 16 | ord(command_buffer[2]) << 8 | ord(command_buffer[3])
                        elif (command == KISS.CMD_STAT_RSSI):
                            self.r_stat_rssi = byte-RNodeInterface.RSSI_OFFSET
                        elif (command == KISS.CMD_STAT_SNR):
                            self.r_stat_snr = int.from_bytes(bytes([byte]), byteorder="big", signed=True) * 0.25
                        elif (command == KISS.CMD_RANDOM):
                            self.r_random = byte
                        elif (command == KISS.CMD_ERROR):
                            if (byte == KISS.ERROR_INITRADIO):
                                RNS.log(str(self)+" hardware initialisation error (code "+RNS.hexrep(byte)+")")
                            elif (byte == KISS.ERROR_INITRADIO):
                                RNS.log(str(self)+" hardware TX error (code "+RNS.hexrep(byte)+")")
                            else:
                                RNS.log(str(self)+" hardware error (code "+RNS.hexrep(byte)+")")
                        elif (command == KISS.CMD_DETECT):
                            if byte == KISS.DETECT_RESP:
                                self.detected = True
                            else:
                                self.detected = False
                        
                else:
                    time_since_last = int(time.time()*1000) - last_read_ms
                    if len(data_buffer) > 0 and time_since_last > self.timeout:
                        RNS.log(str(self)+" serial read timeout")
                        data_buffer = b""
                        in_frame = False
                        command = KISS.CMD_UNKNOWN
                        escape = False
                    sleep(0.08)

        except Exception as e:
            raise e
            exit()

    def updateBitrate(self):
        try:
            self.bitrate = self.r_sf * ( (4.0/self.r_cr) / (math.pow(2,self.r_sf)/(self.r_bandwidth/1000)) ) * 1000
            self.bitrate_kbps = round(self.bitrate/1000.0, 2)
        except Exception as e:
            self.bitrate = 0

    def updateVersion(self):
        minstr = str(self.minor_version)
        if len(minstr) == 1:
            minstr = "0"+minstr
        self.version = str(self.major_version)+"."+minstr

    def detect(self):
        kiss_command = bytes([KISS.FEND, KISS.CMD_DETECT, KISS.DETECT_REQ, KISS.FEND, KISS.CMD_FW_VERSION, 0x00, KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while configuring spreading factor for "+self(str))

    def initRadio(self):
        self.setFrequency()
        self.setBandwidth()
        self.setTXPower()
        self.setSpreadingFactor()
        self.setCodingRate()
        self.setRadioState(KISS.RADIO_STATE_ON)

    def setFrequency(self):
        c1 = self.frequency >> 24
        c2 = self.frequency >> 16 & 0xFF
        c3 = self.frequency >> 8 & 0xFF
        c4 = self.frequency & 0xFF
        data = KISS.escape(bytes([c1])+bytes([c2])+bytes([c3])+bytes([c4]))

        kiss_command = bytes([KISS.FEND])+bytes([KISS.CMD_FREQUENCY])+data+bytes([KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while configuring frequency for "+self(str))

    def setBandwidth(self):
        c1 = self.bandwidth >> 24
        c2 = self.bandwidth >> 16 & 0xFF
        c3 = self.bandwidth >> 8 & 0xFF
        c4 = self.bandwidth & 0xFF
        data = KISS.escape(bytes([c1])+bytes([c2])+bytes([c3])+bytes([c4]))

        kiss_command = bytes([KISS.FEND])+bytes([KISS.CMD_BANDWIDTH])+data+bytes([KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while configuring bandwidth for "+self(str))

    def setTXPower(self):
        txp = bytes([self.txpower])
        kiss_command = bytes([KISS.FEND])+bytes([KISS.CMD_TXPOWER])+txp+bytes([KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while configuring TX power for "+self(str))

    def setSpreadingFactor(self):
        sf = bytes([self.sf])
        kiss_command = bytes([KISS.FEND])+bytes([KISS.CMD_SF])+sf+bytes([KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while configuring spreading factor for "+self(str))

    def setCodingRate(self):
        cr = bytes([self.cr])
        kiss_command = bytes([KISS.FEND])+bytes([KISS.CMD_CR])+cr+bytes([KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while configuring coding rate for "+self(str))

    def setRadioState(self, state):
        kiss_command = bytes([KISS.FEND])+bytes([KISS.CMD_RADIO_STATE])+bytes([state])+bytes([KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while configuring radio state for "+self(str))

    def setNormalMode(self):
        kiss_command = bytes([KISS.FEND, KISS.CMD_CONF_DELETE, 0x00, KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while configuring device mode")

    def setTNCMode(self):
        kiss_command = bytes([KISS.FEND, KISS.CMD_CONF_SAVE, 0x00, KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while configuring device mode")

    def wipe_eeprom(self):
        kiss_command = bytes([KISS.FEND, KISS.CMD_ROM_WIPE, 0xf8, KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while wiping EEPROM")
        sleep(13);

    def write_eeprom(self, addr, byte):
        write_payload = b"" + bytes([addr, byte])
        write_payload = KISS.escape(write_payload)
        kiss_command = bytes([KISS.FEND, KISS.CMD_ROM_WRITE]) + write_payload + bytes([KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while writing EEPROM")


    def download_eeprom(self):
        kiss_command = bytes([KISS.FEND, KISS.CMD_ROM_READ, 0x00, KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while configuring radio state")

        sleep(0.2)
        if self.eeprom == None:
            RNS.log("Could not download EEPROM from device. Is a valid firmware installed?")
            exit()
        else:
            self.parse_eeprom()

    def parse_eeprom(self):
        if self.eeprom[ROM.ADDR_INFO_LOCK] == ROM.INFO_LOCK_BYTE:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend

            self.provisioned = True

            self.product = self.eeprom[ROM.ADDR_PRODUCT]
            self.model = self.eeprom[ROM.ADDR_MODEL]
            self.hw_rev = self.eeprom[ROM.ADDR_HW_REV]
            self.serialno = bytes([self.eeprom[ROM.ADDR_SERIAL], self.eeprom[ROM.ADDR_SERIAL+1], self.eeprom[ROM.ADDR_SERIAL+2], self.eeprom[ROM.ADDR_SERIAL+3]])
            self.made = bytes([self.eeprom[ROM.ADDR_MADE], self.eeprom[ROM.ADDR_MADE+1], self.eeprom[ROM.ADDR_MADE+2], self.eeprom[ROM.ADDR_MADE+3]])
            self.checksum = b""


            self.min_freq = ranges[self.model][0]
            self.max_freq = ranges[self.model][1]
            self.max_output = ranges[self.model][2]

            try:
                self.min_freq = ranges[self.model][0]
                self.max_freq = ranges[self.model][1]
                self.max_output = ranges[self.model][2]
            except Exception as e:
                RNS.log("Exception")
                RNS.log(str(e))
                self.min_freq = 0
                self.max_freq = 0
                self.max_output = 0

            for i in range(0,16):
                self.checksum = self.checksum+bytes([self.eeprom[ROM.ADDR_CHKSUM+i]])

            self.signature = b""
            for i in range(0,128):
                self.signature = self.signature+bytes([self.eeprom[ROM.ADDR_SIGNATURE+i]])

            checksummed_info = b"" + bytes([self.product]) + bytes([self.model]) + bytes([self.hw_rev]) + self.serialno + self.made
            digest = hashes.Hash(hashes.MD5(), backend=default_backend())
            digest.update(checksummed_info)
            checksum = digest.finalize()

            if self.checksum != checksum:
                self.provisioned = False
                RNS.log("EEPROM checksum mismatch")
                exit()
            else:
                RNS.log("EEPROM checksum correct")
                from cryptography.hazmat.primitives.serialization import load_der_public_key
                from cryptography.hazmat.primitives.serialization import load_der_private_key
                from cryptography.hazmat.primitives.asymmetric import padding
                for known in known_keys:
                    vendor = known[0]
                    public_hexrep = known[1]
                    public_bytes = bytes.fromhex(public_hexrep)
                    public_key = load_der_public_key(public_bytes, backend=default_backend())
                    try:
                        public_key.verify(
                            self.signature,
                            self.checksum,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256())
                        RNS.log("Board signature validated")
                        self.signature_valid = True
                        self.vendor = vendor
                    except Exception as e:
                        RNS.log("Board signature validation failed")

            if self.eeprom[ROM.ADDR_CONF_OK] == ROM.CONF_OK_BYTE:
                self.configured = True
                self.conf_sf = self.eeprom[ROM.ADDR_CONF_SF]
                self.conf_cr = self.eeprom[ROM.ADDR_CONF_CR]
                self.conf_txpower = self.eeprom[ROM.ADDR_CONF_TXP]
                self.conf_frequency = self.eeprom[ROM.ADDR_CONF_FREQ] << 24 | self.eeprom[ROM.ADDR_CONF_FREQ+1] << 16 | self.eeprom[ROM.ADDR_CONF_FREQ+2] << 8 | self.eeprom[ROM.ADDR_CONF_FREQ+3]
                self.conf_bandwidth = self.eeprom[ROM.ADDR_CONF_BW] << 24 | self.eeprom[ROM.ADDR_CONF_BW+1] << 16 | self.eeprom[ROM.ADDR_CONF_BW+2] << 8 | self.eeprom[ROM.ADDR_CONF_BW+3]
            else:
                self.configured = False
        else:
            self.provisioned = False


    def device_probe(self):
        sleep(2.5)
        self.detect()
        sleep(0.1)
        if self.detected == True:
            RNS.log("Device connected")
            RNS.log("Firmware version: "+self.version)
            return True
        else:
            raise IOError("Got invalid response while detecting device")

def main():
    try:
        if not util.find_spec("serial"):
            raise ImportError("Serial module could not be found")
    except ImportError:
        print("")
        print("RNode Config Utility needs pyserial to work.")
        print("You can install it with: pip3 install pyserial")
        print("")
        exit()

    try:
        if not util.find_spec("cryptography"):
            raise ImportError("Cryptography module could not be found")
    except ImportError:
        print("")
        print("RNode Config Utility needs the cryptography module to work.")
        print("You can install it with: pip3 install cryptography")
        print("")
        exit()

    import serial

    try:
        parser = argparse.ArgumentParser(description="RNode Configuration and firmware utility. This program allows you to change various settings and startup modes of RNode. It can also flash and update the firmware, and manage device EEPROM.")
        parser.add_argument("-i", "--info", action="store_true", help="Show device info")
        parser.add_argument("-T", "--tnc", action="store_true", help="Switch device to TNC mode")
        parser.add_argument("-N", "--normal", action="store_true", help="Switch device to normal mode")
        parser.add_argument("-b", "--backup", action="store_true", help="Backup EEPROM to file")
        parser.add_argument("-d", "--dump", action="store_true", help="Dump EEPROM to console")
        parser.add_argument("-f", "--flash", action="store_true", help="Flash firmware and bootstrap EEPROM")
        parser.add_argument("-r", "--rom", action="store_true", help="Bootstrap EEPROM without flashing firmware")
        parser.add_argument("-u", "--update", action="store_true", help="Update firmware")
        parser.add_argument("-k", "--key", action="store_true", help="Generate a new signing key and exit")
        parser.add_argument("-p", "--public", action="store_true", help="Display public part of signing key")
        parser.add_argument("--freq", action="store", metavar="Hz", type=int, default=None, help="Frequency in Hz for TNC mode")
        parser.add_argument("--bw", action="store", metavar="Hz", type=int, default=None, help="Bandwidth in Hz for TNC mode")
        parser.add_argument("--txp", action="store", metavar="dBm", type=int, default=None, help="TX power in dBm for TNC mode")
        parser.add_argument("--sf", action="store", metavar="factor", type=int, default=None, help="Spreading factor for TNC mode (7 - 12)")
        parser.add_argument("--cr", action="store", metavar="rate", type=int, default=None, help="Coding rate for TNC mode (5 - 8)")
        parser.add_argument("--model", action="store", metavar="model", type=str, default=None, help="Model code for EEPROM bootstrap")
        parser.add_argument("--hwrev", action="store", metavar="revision", type=int, default=None, help="Hardware revision EEPROM bootstrap")
        parser.add_argument("--nocheck", action="store_true", help="Don't check for firmware updates online")
        parser.add_argument("--eepromwipe", action="store_true", help="Unlock and wipe EEPROM")     

        parser.add_argument("port", nargs="?", default=None, help="serial port where RNode is attached", type=str)
        args = parser.parse_args()

        if args.public or args.key or args.flash or args.rom:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            from cryptography.hazmat.primitives.serialization import load_der_private_key
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives.asymmetric import padding

        if args.public:
            private_bytes = None
            try:
                file = open("./firmware/signing.key", "rb")
                private_bytes = file.read()
                file.close()
            except Exception as e:
                RNS.log("Could not load signing key")

            try:
                private_key = serialization.load_der_private_key(
                    private_bytes,
                    password=None,
                    backend=default_backend()
                )
                public_key = private_key.public_key()
                public_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                RNS.log("Public key:")
                RNS.log(RNS.hexrep(public_bytes, delimit=False))
            except Exception as e:
                RNS.log("Could not deserialize signing key")
                RNS.log(str(e))

            exit()

        if args.key:
            RNS.log("Generating a new signing key...")
            private_key = rsa.generate_private_key(
                public_exponent=65337,
                key_size=1024,
                backend=default_backend()
            )
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_key = private_key.public_key()
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if os.path.isdir("./firmware"):
                if os.path.isfile("./firmware/signing.key"):
                    RNS.log("Signing key already exists, not overwriting!")
                    RNS.log("Manually delete this key to create a new one.")
                else:
                    file = open("./firmware/signing.key", "wb")
                    file.write(private_bytes)
                    file.close()

                    RNS.log("Wrote signing key")
                    RNS.log("Public key:")
                    RNS.log(RNS.hexrep(public_bytes, delimit=False))
            else:
                RNS.log("The firmware directory does not exist, can't write key!")

            exit()

        if args.port:
            if args.update:
                if not args.nocheck:
                    try:
                        RNS.log("Downloading latest firmware from GitHub...")
                        os.makedirs("update", exist_ok=True)
                        urlretrieve(firmware_update_url, "update/rnode_update.hex")
                        RNS.log("Firmware download completed")
                        if os.path.isfile("./update/rnode_update.hex"):
                            try:
                                RNS.log("Updating RNode firmware for device on "+args.port)
                                from subprocess import call
                                flash_status = call(["avrdude", "-P", args.port, "-p", "m1284p", "-c", "arduino", "-b", "115200", "-U", "flash:w:update/rnode_update.hex"])
                                if flash_status == 0:
                                    RNS.log("Firmware updated")
                                    args.info = True
                                else:
                                    exit()

                            except Exception as e:
                                RNS.log("Error while updating firmware")
                                RNS.log(str(e))
                        else:
                            RNS.log("Firmware update file not found")
                            exit()

                    except Exception as e:
                        RNS.log("Could not download firmware update")
                        RNS.log("The contained exception was: "+str(e))
                        exit()

            if args.flash:
                if os.path.isfile("./firmware/rnode_firmware.hex"):
                    try:
                        RNS.log("Flashing RNode firmware to device on "+args.port)
                        from subprocess import call
                        flash_status = call(["avrdude", "-P", args.port, "-p", "m1284p", "-c", "arduino", "-b", "115200", "-U", "flash:w:firmware/rnode_firmware.hex"])
                        if flash_status == 0:
                            RNS.log("Done flashing")
                            args.rom = True
                        else:
                            exit()

                    except Exception as e:
                        RNS.log("Error while flashing")
                        RNS.log(str(e))
                else:
                    RNS.log("Firmware file not found")
                    exit()

            RNS.log("Opening serial port "+args.port+"...")
            try:
                rnode_serial = serial.Serial(
                    port = args.port,
                    baudrate = rnode_baudrate,
                    bytesize = 8,
                    parity = serial.PARITY_NONE,
                    stopbits = 1,
                    xonxoff = False,
                    rtscts = False,
                    timeout = 0,
                    inter_byte_timeout = None,
                    write_timeout = None,
                    dsrdtr = False
                )
            except Exception as e:
                RNS.log("Could not open the specified serial port. The contained exception was:")
                RNS.log(str(e))
                exit()

            rnode = RNode(rnode_serial)
            thread = threading.Thread(target=rnode.readLoop)
            thread.setDaemon(True)
            thread.start()

            try:
                rnode.device_probe()
            except Exception as e:
                RNS.log("Serial port opened, but RNode did not respond. Is a valid firmware installed?")
                print(e)
                exit()

            RNS.log("Reading EEPROM...")
            rnode.download_eeprom()

            if args.eepromwipe:
                RNS.log("WARNING: EEPROM is being wiped!")
                rnode.wipe_eeprom()

            if args.dump:
                RNS.log("EEPROM contents:")
                RNS.log(RNS.hexrep(rnode.eeprom))
                exit()

            if args.backup:
                try:
                    timestamp = time.time()
                    filename = str(time.strftime("%Y-%m-%d_%H-%M-%S"))
                    path = "./eeprom/"+filename+".eeprom"
                    file = open(path, "wb")
                    file.write(rnode.eeprom)
                    file.close()
                    RNS.log("EEPROM backup written to: "+path)
                except Exception as e:
                    RNS.log("EEPROM was successfully downloaded from device,")
                    RNS.log("but file could not be written to disk.")
                exit()

            if args.info:
                if rnode.provisioned:
                    timestamp = struct.unpack(">I", rnode.made)[0]
                    timestring = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                    sigstring = "Unverified"
                    if rnode.signature_valid:
                        sigstring = "Genuine board, vendor is "+rnode.vendor

                    RNS.log("")
                    RNS.log("Board info:")
                    RNS.log("\tFirmware version:\t"+rnode.version)
                    RNS.log("\tProduct code:\t\t"+bytes([rnode.product]).hex())
                    RNS.log("\tModel code:\t\t"+bytes([rnode.model]).hex())
                    RNS.log("\tHardware revision:\t"+bytes([rnode.hw_rev]).hex())
                    RNS.log("\tSerial number:\t\t"+RNS.hexrep(rnode.serialno))
                    RNS.log("\tFrequency range:\t"+str(rnode.min_freq/1e6)+" MHz - "+str(rnode.max_freq/1e6)+" MHz")
                    RNS.log("\tMax TX power:\t\t"+str(rnode.max_output)+" dBm")
                    RNS.log("\tManufactured:\t\t"+timestring)

                    if rnode.configured:
                        rnode.bandwidth = rnode.conf_bandwidth
                        rnode.r_bandwidth = rnode.conf_bandwidth
                        rnode.sf = rnode.conf_sf
                        rnode.r_sf = rnode.conf_sf
                        rnode.cr = rnode.conf_cr
                        rnode.r_cr = rnode.conf_cr
                        rnode.updateBitrate()
                        txp_mw = round(pow(10, (rnode.conf_txpower/10)), 3)
                        RNS.log("\tDevice signature:\t"+sigstring)
                        RNS.log("");
                        RNS.log("\tDevice mode:\t\tTNC")
                        RNS.log("\t  Frequency:\t\t"+str((rnode.conf_frequency/1000000.0))+" MHz")
                        RNS.log("\t  Bandwidth:\t\t"+str(rnode.conf_bandwidth/1000.0)+" KHz")
                        RNS.log("\t  TX power:\t\t"+str(rnode.conf_txpower)+" dBm ("+str(txp_mw)+" mW)")
                        RNS.log("\t  Spreading factor:\t"+str(rnode.conf_sf))
                        RNS.log("\t  Coding rate:\t\t"+str(rnode.conf_cr))
                        RNS.log("\t  On-air bitrate:\t"+str(rnode.bitrate_kbps)+" kbps")
                    else:
                        RNS.log("\tDevice mode:\t\tNormal (host-controlled)")
                        RNS.log("\tDevice signature:\t"+sigstring)

                    print("")
                    exit()

                else:
                    RNS.log("EEPROM is invalid, no further information available")
                    exit()

            if args.rom:
                if rnode.provisioned:
                    RNS.log("EEPROM bootstrap was requested, but a valid EEPROM was already present.")
                    RNS.log("No changes are being made.")
                    exit()
                else:
                    counter = None
                    counter_path = "./firmware/serial.counter"
                    try:
                        if os.path.isfile(counter_path):
                            file = open(counter_path, "r")
                            counter_str = file.read()
                            counter = int(counter_str)
                            file.close()
                        else:
                            counter = 0
                    except Exception as e:
                        RNS.log("Could not create device serial number, exiting")
                        RNS.log(str(e))
                        exit()

                    serialno = counter+1
                    model = None
                    hwrev = None
                    if args.model == "a4":
                        model = ROM.MODEL_A4
                    if args.model == "a9":
                        model = ROM.MODEL_A9
                    if args.hwrev > 0 and args.hwrev < 256:
                        hwrev = chr(args.hwrev)

                    if serialno > 0 and model != None and hwrev != None:
                        try:
                            from cryptography.hazmat.primitives import hashes
                            from cryptography.hazmat.backends import default_backend

                            timestamp = int(time.time())
                            time_bytes = struct.pack(">I", timestamp)
                            serial_bytes = struct.pack(">I", serialno)
                            file = open(counter_path, "w")
                            file.write(str(serialno))
                            file.close()

                            info_chunk  = b"" + bytes([ROM.PRODUCT_RNODE, model, ord(hwrev)])
                            info_chunk += serial_bytes
                            info_chunk += time_bytes
                            digest = hashes.Hash(hashes.MD5(), backend=default_backend())
                            digest.update(info_chunk)
                            checksum = digest.finalize()

                            RNS.log("Loading signing key...")
                            signature = None
                            key_path = "./firmware/signing.key"
                            if os.path.isfile(key_path):
                                try:
                                    file = open(key_path, "rb")
                                    private_bytes = file.read()
                                    file.close()
                                    private_key = serialization.load_der_private_key(
                                        private_bytes,
                                        password=None,
                                        backend=default_backend()
                                    )
                                    public_key = private_key.public_key()
                                    public_bytes = public_key.public_bytes(
                                        encoding=serialization.Encoding.DER,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                                    )
                                    signature = private_key.sign(
                                        checksum,
                                        padding.PSS(
                                            mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.MAX_LENGTH
                                        ),
                                        hashes.SHA256()
                                    )
                                except Exception as e:
                                    RNS.log("Error while signing EEPROM")
                                    RNS.log(str(e))
                            else:
                                RNS.log("No signing key found")
                                exit()


                            RNS.log("Bootstrapping device EEPROM...")

                            rnode.write_eeprom(ROM.ADDR_PRODUCT, ROM.PRODUCT_RNODE)
                            time.sleep(0.006)
                            rnode.write_eeprom(ROM.ADDR_MODEL, model)
                            time.sleep(0.006)
                            rnode.write_eeprom(ROM.ADDR_HW_REV, ord(hwrev))
                            time.sleep(0.006)
                            rnode.write_eeprom(ROM.ADDR_SERIAL, serial_bytes[0])
                            time.sleep(0.006)
                            rnode.write_eeprom(ROM.ADDR_SERIAL+1, serial_bytes[1])
                            time.sleep(0.006)
                            rnode.write_eeprom(ROM.ADDR_SERIAL+2, serial_bytes[2])
                            time.sleep(0.006)
                            rnode.write_eeprom(ROM.ADDR_SERIAL+3, serial_bytes[3])
                            time.sleep(0.006)
                            rnode.write_eeprom(ROM.ADDR_MADE, time_bytes[0])
                            time.sleep(0.006)
                            rnode.write_eeprom(ROM.ADDR_MADE+1, time_bytes[1])
                            time.sleep(0.006)
                            rnode.write_eeprom(ROM.ADDR_MADE+2, time_bytes[2])
                            time.sleep(0.006)
                            rnode.write_eeprom(ROM.ADDR_MADE+3, time_bytes[3])
                            time.sleep(0.006)

                            for i in range(0,16):
                                rnode.write_eeprom(ROM.ADDR_CHKSUM+i, checksum[i])
                                time.sleep(0.006)

                            for i in range(0,128):
                                rnode.write_eeprom(ROM.ADDR_SIGNATURE+i, signature[i])
                                time.sleep(0.006)

                            rnode.write_eeprom(ROM.ADDR_INFO_LOCK, ROM.INFO_LOCK_BYTE)

                            RNS.log("EEPROM written! Validating...")
                            rnode.download_eeprom()
                            if rnode.provisioned:
                                RNS.log("EEPROM Bootstrapping successful!")
                                try:
                                    file = open("./firmware/device_db/"+serial_bytes.hex(), "wb")
                                    written = file.write(rnode.eeprom)
                                    file.close()
                                except Exception as e:
                                    RNS.log("WARNING: Could not backup device EEPROM to disk")
                                exit()
                            else:
                                RNS.log("EEPROM was written, but validation failed. Check your settings.")
                                exit()
                        except Exception as e:
                            RNS.log("An error occurred while writing EEPROM. The contained exception was:")
                            RNS.log(str(e))
                            raise e

                    else:
                        RNS.log("Invalid data specified, cancelling EEPROM write")
                        exit()


            if rnode.provisioned:
                if args.normal:
                    rnode.setNormalMode()
                    RNS.log("Device set to normal (host-controlled) operating mode")
                    exit()
                if args.tnc:
                    if not (args.freq and args.bw and args.txp and args.sf and args.cr):
                        RNS.log("Please input startup configuration:")

                    print("")
                    if args.freq:
                        rnode.frequency = args.freq
                    else:
                        print("Frequency in Hz:\t", end="")
                        rnode.frequency = int(input())


                    if args.bw:
                        rnode.bandwidth = args.bw
                    else:
                        print("Bandwidth in Hz:\t", end="")
                        rnode.bandwidth = int(input())

                    if args.txp != None and (args.txp >= 0 and args.txp <= 17):
                        rnode.txpower = args.txp
                    else:
                        print("TX Power in dBm:\t", end="")
                        rnode.txpower = int(input())

                    if args.sf:
                        rnode.sf = args.sf
                    else:
                        print("Spreading factor:\t", end="")
                        rnode.sf = int(input())

                    if args.cr:
                        rnode.cr = args.cr
                    else:
                        print("Coding rate:\t\t", end="")
                        rnode.cr = int(input())

                    print("")

                    rnode.initRadio()
                    sleep(0.5)
                    rnode.setTNCMode()
                    RNS.log("Device set to TNC operating mode")
                    sleep(1.0)

                    exit()
            else:
                RNS.log("This device contains a valid firmware, but EEPROM is invalid.")
                RNS.log("Probably the device has not been initialised, or the EEPROM has been erased.")
                RNS.log("Please correctly initialise the device and try again!")

        else:
            print("")
            parser.print_help()
            print("")
            exit()


    except KeyboardInterrupt:
        print("")
        exit()

if __name__ == "__main__":
    main()