#!python3

# MIT License
#
# Copyright (c) 2018 Mark Qvist - unsigned.io/rnode
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

program_version = "1.1.5"
eth_addr = "0x81F7B979fEa6134bA9FD5c701b3501A2e61E897a"
btc_addr = "3CPmacGm34qYvR6XWLVEJmi2aNe3PZqUuq"

rnode = None
rnode_serial = None
rnode_port = None
rnode_baudrate = 115200
known_keys = [["unsigned.io", "30819f300d06092a864886f70d010101050003818d0030818902818100bf831ebd99f43b477caf1a094bec829389da40653e8f1f83fc14bf1b98a3e1cc70e759c213a43f71e5a47eb56a9ca487f241335b3e6ff7cdde0ee0a1c75c698574aeba0485726b6a9dfc046b4188e3520271ee8555a8f405cf21f81f2575771d0b0887adea5dd53c1f594f72c66b5f14904ffc2e72206a6698a490d51ba1105b0203010001"], ["unsigned.io", "30819f300d06092a864886f70d010101050003818d0030818902818100e5d46084e445595376bf7efd9c6ccf19d39abbc59afdb763207e4ff68b8d00ebffb63847aa2fe6dd10783d3ea63b55ac66f71ad885c20e223709f0d51ed5c6c0d0b093be9e1d165bb8a483a548b67a3f7a1e4580f50e75b306593fa6067ae259d3e297717bd7ff8c8f5b07f2bed89929a9a0321026cf3699524db98e2d18fb2d020300ff39"]]
firmware_update_url = "https://github.com/markqvist/RNode_Firmware/raw/master/Precompiled/"
fw_filename = None
mapped_model = None

class RNS():
    @staticmethod
    def log(msg):
        logtimefmt   = "%Y-%m-%d %H:%M:%S"
        timestamp = time.time()
        logstring = "["+time.strftime(logtimefmt)+"] "+msg
        print(logstring)

    @staticmethod
    def hexrep(data, delimit=True):
        try:
            iter(data)
        except TypeError:
            data = [data]

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
    CMD_PLATFORM    = 0x48
    CMD_MCU         = 0x49
    CMD_FW_VERSION  = 0x50
    CMD_ROM_READ    = 0x51
    CMD_ROM_WRITE   = 0x52
    CMD_ROM_WIPE    = 0x59
    CMD_CONF_SAVE   = 0x53
    CMD_CONF_DELETE = 0x54
    CMD_RESET       = 0x55

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
    PLATFORM_AVR   = 0x90
    PLATFORM_ESP32 = 0x80

    MCU_1284P      = 0x91
    MCU_2560       = 0x92
    MCU_ESP32      = 0x81

    PRODUCT_RNODE  = 0x03
    MODEL_A4       = 0xA4
    MODEL_A9       = 0xA9

    PRODUCT_TBEAM  = 0xE0
    MODEL_E4       = 0xE4
    MODEL_E9       = 0xE9
    
    PRODUCT_HMBRW  = 0xF0
    MODEL_FF       = 0xFF

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

mapped_product = ROM.PRODUCT_RNODE
products = {
    ROM.PRODUCT_RNODE: "RNode",
    ROM.PRODUCT_HMBRW: "Hombrew RNode",
    ROM.PRODUCT_TBEAM: "LilyGO T-Beam",
}

platforms = {
    ROM.PLATFORM_AVR: "AVR",
    ROM.PLATFORM_ESP32:"ESP32",
}

mcus = {
    ROM.MCU_1284P: "ATmega1284P",
    ROM.MCU_2560:"ATmega2560",
    ROM.MCU_ESP32:"Espressif Systems ESP32",
}

models = {
    0xA4: [410000000, 525000000, 14, "410 - 525 MHz", "rnode_firmware_latest.hex"],
    0xA9: [820000000, 1020000000, 17, "820 - 1020 MHz", "rnode_firmware_latest.hex"],
    0xF4: [410000000, 525000000, 14, "410 - 525 MHz", "rnode_firmware_latest_m2560.hex"],
    0xF9: [820000000, 1020000000, 17, "820 - 1020 MHz", "rnode_firmware_latest_m2560.hex"],
    0xE4: [420000000, 520000000, 14, "420 - 520 MHz", "rnode_firmware_latest_tbeam.zip"],
    0xE9: [850000000, 950000000, 17, "850 - 950 MHz", "rnode_firmware_latest_tbeam.zip"],
    0xFF: [100000000, 1100000000, 14, "(Band capabilities unknown)"],
}

squashvw = False

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

        self.platform = None
        self.mcu = None
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
        self.locally_signed = False
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

    def disconnect(self):
        self.serial.close()

    def readLoop(self):
        try:
            in_frame = False
            escape = False
            command = KISS.CMD_UNKNOWN
            data_buffer = b""
            command_buffer = b""
            last_read_ms = int(time.time()*1000)

            while self.serial.is_open:
                try:
                    data_waiting = self.serial.in_waiting
                except Exception as e:
                    data_waiting = False

                if data_waiting:
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

                        elif (command == KISS.CMD_PLATFORM):
                            self.platform = byte

                        elif (command == KISS.CMD_MCU):
                            self.mcu = byte

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
                            elif (byte == KISS.ERROR_TXFAILED):
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
        kiss_command = bytes([KISS.FEND, KISS.CMD_DETECT, KISS.DETECT_REQ, KISS.FEND, KISS.CMD_FW_VERSION, 0x00, KISS.FEND, KISS.CMD_PLATFORM, 0x00, KISS.FEND, KISS.CMD_MCU, 0x00, KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while detecting hardware for "+self(str))

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

    def hard_reset(self):
        kiss_command = bytes([KISS.FEND, KISS.CMD_RESET, 0xf8, KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while restarting device")
        sleep(2);

    def write_eeprom(self, addr, byte):
        write_payload = b"" + bytes([addr, byte])
        write_payload = KISS.escape(write_payload)
        kiss_command = bytes([KISS.FEND, KISS.CMD_ROM_WRITE]) + write_payload + bytes([KISS.FEND])
        written = self.serial.write(kiss_command)
        if written != len(kiss_command):
            raise IOError("An IO error occurred while writing EEPROM")


    def download_eeprom(self):
        self.eeprom = None
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
        global squashvw;
        try:
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


                self.min_freq = models[self.model][0]
                self.max_freq = models[self.model][1]
                self.max_output = models[self.model][2]

                try:
                    self.min_freq = models[self.model][0]
                    self.max_freq = models[self.model][1]
                    self.max_output = models[self.model][2]
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

                    from cryptography.hazmat.primitives import serialization
                    from cryptography.hazmat.primitives.serialization import load_der_public_key
                    from cryptography.hazmat.primitives.serialization import load_der_private_key
                    from cryptography.hazmat.primitives.asymmetric import padding

                    # Try loading local signing key for 
                    # validation of self-signed devices
                    if os.path.isdir("./firmware") and os.path.isfile("./firmware/signing.key"):
                        private_bytes = None
                        try:
                            file = open("./firmware/signing.key", "rb")
                            private_bytes = file.read()
                            file.close()
                        except Exception as e:
                            RNS.log("Could not load local signing key")

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
                            public_bytes_hex = RNS.hexrep(public_bytes, delimit=False)

                            vendor_keys = []
                            for known in known_keys:
                                vendor_keys.append(known[1])

                            if not public_bytes_hex in vendor_keys:
                                local_key_entry = ["LOCAL", public_bytes_hex]
                                known_keys.append(local_key_entry)

                        except Exception as e:
                            RNS.log("Could not deserialize local signing key")
                            RNS.log(str(e))

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
                            if vendor == "LOCAL":
                                self.locally_signed = True

                            self.signature_valid = True
                            self.vendor = vendor
                        except Exception as e:
                            pass

                    if self.signature_valid:
                        RNS.log("Device signature validated")
                    else:
                        RNS.log("Device signature validation failed")
                        if not squashvw:
                            print("     ")
                            print("     WARNING! This device is NOT verifiable and should NOT be trusted.")
                            print("     Someone could have added privacy-breaking or malicious code to it.")
                            print("     ")
                            print("     Proceed at your own risk and responsibility! If you created this")
                            print("     device yourself, please read the documentation on how to sign your")
                            print("     device to avoid this warning.")
                            print("     ")
                            print("     Always use a firmware downloaded as binaries or compiled from source")
                            print("     from one of the following locations:")
                            print("     ")
                            print("        https://unsigned.io/rnode")
                            print("        https://github.com/markqvist/rnode_firmware")
                            print("     ")
                            print("     You can reflash and bootstrap this device to a verifiable state")
                            print("     by using this utility. It is recommended to do so NOW!")
                            print("     ")
                            print("     To initialise this device to a verifiable state, please run:")
                            print("     ")
                            print("              rnodeconf "+str(self.serial.name)+" --autoinstall")
                            print("")



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
        except Exception as e:
            self.provisioned = False
            RNS.log("Invalid EEPROM data, could not parse device EEPROM.")


    def device_probe(self):
        sleep(2.5)
        self.detect()
        sleep(0.1)
        if self.detected == True:
            RNS.log("Device connected")
            RNS.log("Current firmware version: "+self.version)
            return True
        else:
            raise IOError("Got invalid response while detecting device")

def rnode_open_serial(port):
    import serial
    return serial.Serial(
        port = port,
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

def main():
    global mapped_product, mapped_model, fw_filename

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
    from serial.tools import list_ports

    try:
        parser = argparse.ArgumentParser(description="RNode Configuration and firmware utility. This program allows you to change various settings and startup modes of RNode. It can also install, flash and update the firmware on supported devices.")
        parser.add_argument("-i", "--info", action="store_true", help="Show device info")
        parser.add_argument("-a", "--autoinstall", action="store_true", help="Automatic installation on various supported devices")
        parser.add_argument("-u", "--update", action="store_true", help="Update firmware to the latest version")
        parser.add_argument("--nocheck", action="store_true", help="Don't check for firmware updates online, use existing local files if possible")
        parser.add_argument("-N", "--normal", action="store_true", help="Switch device to normal mode")
        parser.add_argument("-T", "--tnc", action="store_true", help="Switch device to TNC mode")

        parser.add_argument("--freq", action="store", metavar="Hz", type=int, default=None, help="Frequency in Hz for TNC mode")
        parser.add_argument("--bw", action="store", metavar="Hz", type=int, default=None, help="Bandwidth in Hz for TNC mode")
        parser.add_argument("--txp", action="store", metavar="dBm", type=int, default=None, help="TX power in dBm for TNC mode")
        parser.add_argument("--sf", action="store", metavar="factor", type=int, default=None, help="Spreading factor for TNC mode (7 - 12)")
        parser.add_argument("--cr", action="store", metavar="rate", type=int, default=None, help="Coding rate for TNC mode (5 - 8)")

        parser.add_argument("-b", "--backup", action="store_true", help="Backup EEPROM to file")
        parser.add_argument("-d", "--dump", action="store_true", help="Dump EEPROM to console")
        parser.add_argument("--eepromwipe", action="store_true", help="Unlock and wipe EEPROM")

        parser.add_argument("--version", action="store_true", help="Print program version and exit")

        parser.add_argument("-f", "--flash", action="store_true", help=argparse.SUPPRESS) # Flash firmware and bootstrap EEPROM
        parser.add_argument("-r", "--rom", action="store_true", help=argparse.SUPPRESS) # Bootstrap EEPROM without flashing firmware
        parser.add_argument("-k", "--key", action="store_true", help=argparse.SUPPRESS) # Generate a new signing key and exit
        parser.add_argument("-p", "--public", action="store_true", help=argparse.SUPPRESS) # Display public part of signing key
        parser.add_argument("--platform", action="store", metavar="platform", type=str, default=None, help=argparse.SUPPRESS) # Platform specification for device bootstrap
        parser.add_argument("--product", action="store", metavar="product", type=str, default=None, help=argparse.SUPPRESS) # Product specification for device bootstrap
        parser.add_argument("--model", action="store", metavar="model", type=str, default=None, help=argparse.SUPPRESS) # Model code for device bootstrap
        parser.add_argument("--hwrev", action="store", metavar="revision", type=int, default=None, help=argparse.SUPPRESS) # Hardware revision for device bootstrap

        parser.add_argument("port", nargs="?", default=None, help="serial port where RNode is attached", type=str)
        args = parser.parse_args()

        def print_donation_block():
            print("  Ethereum : "+eth_addr)
            print("  Bitcoin  : "+btc_addr)
            print("  Ko-Fi    : https://ko-fi.com/markqvist")
            print("")
            print("  Info     : https://unsigned.io/")
            print("  Code     : https://github.com/markqvist")

        if args.version:
            print("rnodeconf "+program_version)
            exit(0)

        if args.public or args.key or args.flash or args.rom or args.autoinstall:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            from cryptography.hazmat.primitives.serialization import load_der_private_key
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives.asymmetric import padding

        if args.autoinstall:
            print("\nHello!\n\nThis guide will help you install the RNode firmware on supported")
            print("and homebrew devices. Please connect the device you wish to set\nup now. Hit enter when it is connected.")
            input()

            global squashvw
            squashvw = True

            selected_port = None
            if not args.port:
                ports = list_ports.comports()
                portlist = []
                for port in ports:
                    portlist.insert(0, port) 
                
                pi = 1
                print("Detected serial ports:")
                for port in portlist:
                    print("  ["+str(pi)+"] "+str(port.device)+" ("+str(port.product)+", "+str(port.serial_number)+")")
                    pi += 1

                print("\nWhat serial port is your device connected to? ", end="")
                try:
                    c_port = int(input())
                    if c_port < 1 or c_port > len(ports):
                        raise ValueError()

                    selected_port = portlist[c_port-1]
                except Exception as e:
                    print("That port does not exist, exiting now.")
                    exit()

                if selected_port == None:
                    print("Could not select port, exiting now.")
                    exit()

                port_path = selected_port.device
                port_product = selected_port.product
                port_serialno = selected_port.serial_number

                print("\nOk, using device on "+str(port_path)+" ("+str(port_product)+", "+str(port_serialno)+")")

            else:
                ports = list_ports.comports()

                for port in ports:
                    if port.device == args.port:
                        selected_port = port

                if selected_port == None:
                    print("Could not find specified port "+str(args.port)+", exiting now")
                    exit()

                port_path = selected_port.device
                port_product = selected_port.product
                port_serialno = selected_port.serial_number

                print("\nUsing device on "+str(port_path))

            print("\nProbing device...")

            try:
                rnode_serial = rnode_open_serial(port_path)
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
                RNS.log("No answer from device")

            if rnode.detected:
                RNS.log("Trying to read EEPROM...")
                rnode.download_eeprom()

            if rnode.provisioned and rnode.signature_valid:
                print("\nThis device is already installed and provisioned. No further action will")
                print("be taken. If you wish to completely reinstall this device, you must first")
                print("wipe the current EEPROM. See the help for more info.\n\nExiting now.")
                exit()

            if rnode.detected:
                print("\nThe device seems to have an RNode firmware installed, but it was not")
                print("provisioned correctly, or it is corrupt. We are going to reinstall the")
                print("correct firmware and provision it.")
            else:
                print("\nIt looks like this is a fresh device with no RNode firmware.")
                
            print("What kind of device is this?\n")
            print("[1] Original RNode")
            print("[2] Homebrew RNode")
            print("[3] LilyGO T-Beam")
            print("\n? ", end="")

            selected_product = None
            try:
                c_dev = int(input())
                if c_dev < 1 or c_dev > 3:
                    raise ValueError()
                elif c_dev == 1:
                    selected_product = ROM.PRODUCT_RNODE
                elif c_dev == 2:
                    selected_product = ROM.PRODUCT_HMBRW
                elif c_dev == 3:
                    selected_product = ROM.PRODUCT_TBEAM
                    print("")
                    print("---------------------------------------------------------------------------")
                    print("Important! Using RNode firmware on T-Beam devices should currently be")
                    print("considered experimental. It is not intended for production or critical use.")
                    print("The currently supplied firmware is provided AS-IS as a courtesey to those")
                    print("who would like to experiment with it. If you want any degree of reliability,")
                    print("please use an actual RNode from unsigned.io. Hit enter to continue.")
                    print("---------------------------------------------------------------------------")
                    input()
            except Exception as e:
                print("That device type does not exist, exiting now.")
                exit()

            selected_platform = None
            selected_model = None
            selected_mcu = None

            if selected_product == ROM.PRODUCT_HMBRW:
                selected_model = ROM.MODEL_FF
                print("\nWhat kind of microcontroller is your board based on?\n")
                print("[1] AVR ATmega1284P")
                print("[2] AVR ATmega2560")
                print("[3] Espressif Systems ESP32")
                print("\n? ", end="")
                try:
                    c_mcu = int(input())
                    if c_mcu < 1 or c_mcu > 3:
                        raise ValueError()
                    elif c_mcu == 1:
                        selected_mcu = ROM.MCU_1284P
                        selected_platform = ROM.PLATFORM_AVR
                    elif c_mcu == 2:
                        selected_mcu = ROM.MCU_2560
                        selected_platform = ROM.PLATFORM_AVR
                    elif c_mcu == 3:
                        selected_mcu = ROM.MCU_ESP32
                        selected_platform = ROM.PLATFORM_ESP32
                    selected_model = ROM.MODEL_FF

                except Exception as e:
                    print("That MCU type does not exist, exiting now.")
                    exit()

            elif selected_product == ROM.PRODUCT_RNODE:
                selected_mcu = ROM.MCU_1284P
                print("\nWhat model is this RNode?\n")
                print("[1] RNode 410 - 525 MHz")
                print("[2] RNode 820 - 1020 MHz")
                print("\n? ", end="")
                try:
                    c_model = int(input())
                    if c_model < 1 or c_model > 2:
                        raise ValueError()
                    elif c_model == 1:
                        selected_model = ROM.MODEL_A4
                        selected_platform = ROM.PLATFORM_AVR
                    elif c_model == 2:
                        selected_model = ROM.MODEL_A9
                        selected_platform = ROM.PLATFORM_AVR
                except Exception as e:
                    print("That model does not exist, exiting now.")
                    exit()

            elif selected_product == ROM.PRODUCT_TBEAM:
                selected_mcu = ROM.MCU_ESP32
                print("\nWhat band is this T-Beam for?\n")
                print("[1] 433 MHz")
                print("[2] 868 MHz")
                print("[3] 915 MHz")
                print("[4] 923 MHz")
                print("\n? ", end="")
                try:
                    c_model = int(input())
                    if c_model < 1 or c_model > 4:
                        raise ValueError()
                    elif c_model == 1:
                        selected_model = ROM.MODEL_E4
                        selected_platform = ROM.PLATFORM_ESP32
                    elif c_model > 1:
                        selected_model = ROM.MODEL_E9
                        selected_platform = ROM.PLATFORM_ESP32
                except Exception as e:
                    print("That band does not exist, exiting now.")
                    exit()

            if selected_model != ROM.MODEL_FF:
                fw_filename = models[selected_model][4]
            else:
                if selected_platform == ROM.PLATFORM_AVR:
                    if selected_mcu == ROM.MCU_1284P:
                        fw_filename = "rnode_firmware_latest.hex"
                    elif selected_mcu == ROM.MCU_2560:
                        # This variant is not released yet
                        #fw_filename = "rnode_firmware_latest_m2560.hex"
                        fw_filename = None
                elif selected_platform == ROM.PLATFORM_ESP32:
                    # This variant is not released yet
                    #fw_filename = "rnode_firmware_latest_esp32.zip"
                    fw_filename = None
            
            if fw_filename == None:
                print("")
                print("Sorry, no firmware for your board currently exists.")
                print("Help making it a reality by contributing code or by")
                print("donating to the project.")
                print("")
                print_donation_block()
                print("")
                exit()

            print("\nOk, that should be all the information we need. Please confirm the following")
            print("summary before proceeding. In the next step, the device will be flashed and")
            print("provisioned, so make that you are satisfied with your choices.\n")

            print("Serial port     : "+str(selected_port.device))
            print("Device type     : "+str(products[selected_product])+" "+str(models[selected_model][3]))
            print("Platform        : "+str(platforms[selected_platform]))
            print("Device MCU      : "+str(mcus[selected_mcu]))
            print("Firmware file   : "+str(fw_filename))

            print("\nIs the above correct? [y/N] ", end="")
            try:
                c_ok = input().lower()
                if c_ok != "y":
                    raise ValueError()
            except Exception as e:
                print("OK, aborting now.")
                exit()

            args.key = True
            args.port = selected_port.device
            args.platform = selected_platform
            args.hwrev = 1
            mapped_model = selected_model
            mapped_product = selected_product
            args.update = False
            args.flash = True

            # TODO: Download firmware file from github here
            try:
                RNS.log("Downloading latest frimware from GitHub...")
                os.makedirs("./update", exist_ok=True)
                urlretrieve(firmware_update_url+fw_filename, "update/"+fw_filename)
                RNS.log("Firmware download completed")
            except Exception as e:
                RNS.log("Could not download firmware package")
                RNS.log("The contained exception was: "+str(e))
                exit()

            rnode.disconnect()

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
                public_exponent=65537,
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
            os.makedirs("./firmware", exist_ok=True)
            if os.path.isdir("./firmware"):
                if os.path.isfile("./firmware/signing.key"):
                    if not args.autoinstall:
                        RNS.log("Signing key already exists, not overwriting!")
                        RNS.log("Manually delete this key to create a new one.")
                else:
                    file = open("./firmware/signing.key", "wb")
                    file.write(private_bytes)
                    file.close()

                    if not squashvw:
                        RNS.log("Wrote signing key")
                        RNS.log("Public key:")
                        RNS.log(RNS.hexrep(public_bytes, delimit=False))
            else:
                RNS.log("The firmware directory does not exist, can't write key!")

            if not args.autoinstall:
                exit()

        def get_flasher_call(platform, fw_filename):
            from shutil import which
            if platform == "unzip":
                flasher = "unzip"
                if which(flasher) is not None:
                    return [flasher, "-o", "./update/"+fw_filename, "-d", "./update/"]
                else:
                    RNS.log("")
                    RNS.log("You do not currently have the \""+flasher+"\" program installed on your system.")
                    RNS.log("Unfortunately, that means we can't proceed, since it is needed to flash your")
                    RNS.log("board. You can install it via your package manager, for example:")
                    RNS.log("")
                    RNS.log("  sudo apt install "+flasher)
                    RNS.log("")
                    RNS.log("Please install \""+flasher+"\" and try again.")
                    exit()
            elif platform == ROM.PLATFORM_AVR:
                flasher = "avrdude"
                if which(flasher) is not None:
                    return [flasher, "-P", args.port, "-p", "m1284p", "-c", "arduino", "-b", "115200", "-U", "flash:w:update/"+fw_filename]
                else:
                    RNS.log("")
                    RNS.log("You do not currently have the \""+flasher+"\" program installed on your system.")
                    RNS.log("Unfortunately, that means we can't proceed, since it is needed to flash your")
                    RNS.log("board. You can install it via your package manager, for example:")
                    RNS.log("")
                    RNS.log("  sudo apt install avrdude")
                    RNS.log("")
                    RNS.log("Please install \""+flasher+"\" and try again.")
                    exit()
            elif platform == ROM.PLATFORM_ESP32:
                flasher = "./update/esptool.py" 
                if which(flasher) is not None:
                    return [
                        flasher,
                        "--chip", "esp32",
                        "--port", args.port,
                        "--baud", "921600",
                        "--before", "default_reset",
                        "--after", "hard_reset",
                        "write_flash", "-z",
                        "--flash_mode", "dio",
                        "--flash_freq", "80m",
                        "--flash_size", "4MB",
                        "0xe000", "./update/rnode_firmware_latest_tbeam.boot_app0",
                        "0x1000", "./update/rnode_firmware_latest_tbeam.bootloader",
                        "0x10000", "./update/rnode_firmware_latest_tbeam.bin",
                        "0x8000", "./update/rnode_firmware_latest_tbeam.partitions",
                    ]
                else:
                    RNS.log("")
                    RNS.log("You do not currently have the \""+flasher+"\" program installed on your system.")
                    RNS.log("Unfortunately, that means we can't proceed, since it is needed to flash your")
                    RNS.log("board. You can install it via your package manager, for example:")
                    RNS.log("")
                    RNS.log("  sudo apt install esptool")
                    RNS.log("")
                    RNS.log("Please install \""+flasher+"\" and try again.")
                    exit()

        if args.port:
            if args.flash:
                from subprocess import call
                
                if fw_filename == None:
                    fw_filename = "rnode_firmware.hex"

                if args.platform == None:
                    args.platform = ROM.PLATFORM_AVR

                if args.autoinstall:
                    fw_src = "./update/"
                else:
                    import shutil
                    shutil.copy("./firmware/"+fw_filename, "./update/"+fw_filename)
                    fw_src = "./update/"

                if os.path.isfile(fw_src+fw_filename):
                    try:
                        if fw_filename.endswith(".zip"):
                            RNS.log("Extracting firmware...")
                            unzip_status = call(get_flasher_call("unzip", fw_filename))
                            if unzip_status == 0:
                                RNS.log("Firmware extracted")
                            else:
                                RNS.log("Could not extract firmware from downloaded zip file")
                                exit()

                        RNS.log("Flashing RNode firmware to device on "+args.port)
                        from subprocess import call
                        flash_status = call(get_flasher_call(args.platform, fw_filename))
                        if flash_status == 0:
                            RNS.log("Done flashing")
                            args.rom = True
                            if args.platform == ROM.PLATFORM_ESP32:
                                RNS.log("Waiting for ESP32 reset...")
                                time.sleep(5)
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
                rnode_port = args.port
                rnode_serial = rnode_open_serial(rnode_port)
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

            if rnode.detected:
                if rnode.platform == None or rnode.mcu == None:
                    rnode.platform = ROM.PLATFORM_AVR
                    rnode.mcu = ROM.MCU_1284P


            if args.eepromwipe:
                RNS.log("WARNING: EEPROM is being wiped! Power down device NOW if you do not want this!")
                rnode.wipe_eeprom()
                exit()

            RNS.log("Reading EEPROM...")
            rnode.download_eeprom()

            if rnode.provisioned:
                if rnode.model != ROM.MODEL_FF:
                    fw_filename = models[rnode.model][4]
                else:
                    if rnode.platform == ROM.PLATFORM_AVR:
                        if rnode.mcu == ROM.MCU_1284P:
                            fw_filename = "rnode_firmware_latest.hex"
                        elif rnode.mcu == ROM.MCU_2560:
                            # This variant is not released yet
                            #fw_filename = "rnode_firmware_latest_m2560.hex"
                            fw_filename = None
                    elif rnode.platform == ROM.PLATFORM_ESP32:
                        # This variant is not released yet
                        #fw_filename = "rnode_firmware_latest_esp32.zip"
                        fw_filename = None

            if args.update:
                rnode.disconnect()
                from subprocess import call

                if not args.nocheck:
                    try:
                        RNS.log("Downloading latest firmware from GitHub...")
                        os.makedirs("./update", exist_ok=True)
                        urlretrieve(firmware_update_url+fw_filename, "update/"+fw_filename)
                        RNS.log("Firmware download completed")
                        if fw_filename.endswith(".zip"):
                            RNS.log("Extracting firmware...")
                            unzip_status = call(get_flasher_call("unzip", fw_filename))
                            if unzip_status == 0:
                                RNS.log("Firmware extracted")
                            else:
                                RNS.log("Could not extract firmware from downloaded zip file")
                                exit()

                    except Exception as e:
                        RNS.log("Could not download firmware update")
                        RNS.log("The contained exception was: "+str(e))
                        exit()
                else:
                    RNS.log("Skipping online check, using local firmware file: "+"./update/"+fw_filename)

                if os.path.isfile("./update/"+fw_filename):
                    try:
                        args.info = False
                        RNS.log("Updating RNode firmware for device on "+args.port)
                        flash_status = call(get_flasher_call(rnode.platform, fw_filename))
                        if flash_status == 0:
                            RNS.log("Flashing new firmware completed")
                            RNS.log("Opening serial port "+args.port+"...")
                            try:
                                rnode_port = args.port
                                rnode_serial = rnode_open_serial(rnode_port)
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

                            if rnode.detected:
                                if rnode.platform == None or rnode.mcu == None:
                                    rnode.platform = ROM.PLATFORM_AVR
                                    rnode.mcu = ROM.MCU_1284P

                                RNS.log("Reading EEPROM...")
                                rnode.download_eeprom()

                                if rnode.provisioned:
                                    if rnode.model != ROM.MODEL_FF:
                                        fw_filename = models[rnode.model][4]
                                    else:
                                        fw_filename = None
                                    args.info = True

                            if args.info:
                                RNS.log("")
                                RNS.log("Firmware update completed successfully")
                        else:
                            RNS.log("An error occurred while flashing the new firmware, exiting now.")
                            exit()

                    except Exception as e:
                        RNS.log("Error while updating firmware")
                        RNS.log(str(e))
                else:
                    RNS.log("Firmware update file not found")
                    exit()

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
                        if rnode.locally_signed:
                            sigstring = "Validated - Local signature"
                        else:
                            sigstring = "Genuine board, vendor is "+rnode.vendor

                    RNS.log("")
                    RNS.log("Device info:")
                    RNS.log("\tProduct            : "+products[rnode.product]+" "+models[rnode.model][3]+" ("+bytes([rnode.product]).hex()+":"+bytes([rnode.model]).hex()+")")
                    RNS.log("\tDevice signature   : "+sigstring)
                    RNS.log("\tFirmware version   : "+rnode.version)
                    RNS.log("\tHardware revision  : "+str(int(rnode.hw_rev)))
                    RNS.log("\tSerial number      : "+RNS.hexrep(rnode.serialno))
                    RNS.log("\tFrequency range    : "+str(rnode.min_freq/1e6)+" MHz - "+str(rnode.max_freq/1e6)+" MHz")
                    RNS.log("\tMax TX power       : "+str(rnode.max_output)+" dBm")
                    RNS.log("\tManufactured       : "+timestring)

                    if rnode.configured:
                        rnode.bandwidth = rnode.conf_bandwidth
                        rnode.r_bandwidth = rnode.conf_bandwidth
                        rnode.sf = rnode.conf_sf
                        rnode.r_sf = rnode.conf_sf
                        rnode.cr = rnode.conf_cr
                        rnode.r_cr = rnode.conf_cr
                        rnode.updateBitrate()
                        txp_mw = round(pow(10, (rnode.conf_txpower/10)), 3)
                        RNS.log("");
                        RNS.log("\tDevice mode        : TNC")
                        RNS.log("\t  Frequency        : "+str((rnode.conf_frequency/1000000.0))+" MHz")
                        RNS.log("\t  Bandwidth        : "+str(rnode.conf_bandwidth/1000.0)+" KHz")
                        RNS.log("\t  TX power         : "+str(rnode.conf_txpower)+" dBm ("+str(txp_mw)+" mW)")
                        RNS.log("\t  Spreading factor : "+str(rnode.conf_sf))
                        RNS.log("\t  Coding rate      : "+str(rnode.conf_cr))
                        RNS.log("\t  On-air bitrate   : "+str(rnode.bitrate_kbps)+" kbps")
                    else:
                        RNS.log("\tDevice mode        : Normal (host-controlled)")

                    print("")
                    exit()

                else:
                    RNS.log("EEPROM is invalid, no further information available")
                    exit()

            if args.rom:
                if rnode.provisioned and not args.autoinstall:
                    RNS.log("EEPROM bootstrap was requested, but a valid EEPROM was already present.")
                    RNS.log("No changes are being made.")
                    exit()

                else:
                    if rnode.signature_valid:
                        RNS.log("EEPROM bootstrap was requested, but a valid EEPROM was already present.")
                        RNS.log("No changes are being made.")
                        exit()
                    else:
                        if args.autoinstall:
                            RNS.log("Clearing old EEPROM, this will take about 15 seconds...")
                            rnode.wipe_eeprom()
                            
                        if rnode.platform == ROM.PLATFORM_ESP32:
                            RNS.log("Waiting for ESP32 reset...")
                            time.sleep(6)
                        else:
                            time.sleep(3)

                    os.makedirs("./firmware", exist_ok=True)
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
                    if args.product != None:
                        if args.product == "03":
                            mapped_product = ROM.PRODUCT_RNODE
                        if args.product == "f0":
                            mapped_product = ROM.PRODUCT_HMBRW
                        if args.product == "e0":
                            mapped_product = ROM.PRODUCT_TBEAM

                    if mapped_model != None:
                        model = mapped_model
                    else:
                        if args.model == "a4":
                            model = ROM.MODEL_A4
                        elif args.model == "a9":
                            model = ROM.MODEL_A9
                        elif args.model == "f4":
                            model = ROM.MODEL_F4
                        elif args.model == "f9":
                            model = ROM.MODEL_F9
                        elif args.model == "e4":
                            model = ROM.MODEL_E4
                        elif args.model == "e9":
                            model = ROM.MODEL_E9
                        elif args.model == "ff":
                            model = ROM.MODEL_FF


                    if args.hwrev != None and (args.hwrev > 0 and args.hwrev < 256):
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

                            info_chunk  = b"" + bytes([mapped_product, model, ord(hwrev)])
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
                            rnode.hard_reset()

                            rnode.write_eeprom(ROM.ADDR_PRODUCT, mapped_product)
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

                            if rnode.platform == ROM.PLATFORM_ESP32:
                                RNS.log("Waiting for ESP32 reset...")
                                time.sleep(5)

                            rnode.download_eeprom()
                            if rnode.provisioned:
                                RNS.log("EEPROM Bootstrapping successful!")
                                rnode.hard_reset()
                                if args.autoinstall:
                                    print("")
                                    print("RNode Firmware autoinstallation complete!")
                                    print("")
                                    print("To use your device with Reticulum, read the documetation at:")
                                    print("")
                                    print("https://markqvist.github.io/Reticulum/manual/gettingstartedfast.html")
                                    print("")
                                    print("Thank you for using this utility! Please help the project by")
                                    print("contributing code and reporting bugs, or by donating!")
                                    print("")
                                    print("Your contributions and donations directly further the realisation")
                                    print("of truly open, free and resilient communications systems.")
                                    print("")
                                    print_donation_block()
                                    print("")
                                try:
                                    os.makedirs("./firmware/device_db/", exist_ok=True)
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
