# RNode Configuration Utility

## Please beware!

This rnodeconf package is outdated! The rnodeconf utility has been moved into the rns package, and the rnodeconf program in this package will no longer be maintained.

Please uninstall the rnodeconf package, and use rnodeconf from the rns package instead:

```
pip uninstall rnodeconf rns
pip install rns --upgrade
```

The updated rnodeconf source code can now be found directly in the [Reticulum Repository](https://github.com/markqvist/reticulum)

## Introduction

Configure, update, flash, backup and install your [RNode](https://unsigned.io/projects/rnode/) (homebrew or official) with this handy utility.

RNode is a flexible LoRa-based transceiver, and this tool allows you to install and configure RNodes built on a variety of different platforms and boards. With this tool you can configure and update existing RNodes, or make your own RNodes from supported boards and modules.

## Supported Devices
Currently the RNode Configuration Utility supports:

- The original RNode from [unsigned.io](https://unsigned.io/)
- Homebrew RNodes based on ATmega1284p boards
- Homebrew RNodes based on ATmega2560 boards
- Homebrew RNodes based on Adafruit Feather ESP32 boards
- Homebrew RNodes based on generic ESP32 boards
- LilyGO T-Beam v1.1 devices
- LilyGO LoRa32 v2.0 devices
- LilyGO LoRa32 v2.1 devices
- Heltec LoRa32 v2 devices

You can use the included autoinstaller to automatically install and provision the RNode firmware on any supported board.

## Installation

The easiest way to install the configuration utility is with pip:

```sh
# If you don't already have pip installed
sudo apt install python3-pip

# Install rnodeconf included in the rns package with pip
pip3 install rns

# Run rnodeconf
rnodeconf --help
```

## Usage Overview

RNode can operate in two modes, host-controlled (default) and TNC mode:

- When RNode is in host-controlled mode, it will stay in standby when powered on, until the host specifies frequency, bandwidth, transmit power and other required parameters. This mode can be enabled by using the -N option of this utility.

- When RNode is in TNC mode, it will configure itself on powerup and enable the radio immediately. This mode can be enabled by using the -T option of this utility (the utility will guide you through the settings if you don't specify them directly).

For a complete description of RNodes capabilities, documentation and more, please refer to the [RNode repository](https://github.com/markqvist/RNode_Firmware).

```
usage: rnodeconf [-h] [-i] [-a] [-u] [--nocheck] [-N] [-T] [--freq Hz] [--bw Hz] [--txp dBm] [--sf factor] [--cr rate] [-b] [-d] [--eepromwipe] [--version]
                 [port]

RNode Configuration and firmware utility. This program allows you to change various settings and startup modes of RNode. It can also install, flash and
update the firmware on supported devices.

positional arguments:
  port               serial port where RNode is attached

options:
  -h, --help         show this help message and exit
  -i, --info         Show device info
  -a, --autoinstall  Automatic installation on various supported devices
  -u, --update       Update firmware to the latest version
  --nocheck          Don't check for firmware updates online, use existing local files if possible
  -N, --normal       Switch device to normal mode
  -T, --tnc          Switch device to TNC mode
  --freq Hz          Frequency in Hz for TNC mode
  --bw Hz            Bandwidth in Hz for TNC mode
  --txp dBm          TX power in dBm for TNC mode
  --sf factor        Spreading factor for TNC mode (7 - 12)
  --cr rate          Coding rate for TNC mode (5 - 8)
  -b, --backup       Backup EEPROM to file
  -d, --dump         Dump EEPROM to console
  --eepromwipe       Unlock and wipe EEPROM
  --version          Print program version and exit
```

## Command Examples

### Show device info

Print info like serial number, hardware revision, model and firmware version.

```sh
rnodeconf /dev/ttyUSB0 -i
```

### Update the firmware

Grab the latest precompiled firmware from the RNode Firmware repository and flash it to the device.

```sh
rnodeconf /dev/ttyUSB0 -u
```

### Start the autoinstaller

Start the autoinstallation guide for turning a compatible device into an RNode.

```sh
rnodeconf --autoinstall
```

### Set RNode to TNC mode

If you just specify the -T option, the utility will ask you for the necessary parameters.

```sh
rnodeconf /dev/ttyUSB0 -T
```

You can also specify all the options on the command line.

```sh
rnodeconf /dev/ttyuUSB0 -T --freq 868000000 --bw 125000 --txp 2 --sf 7 --cr 5
```

### Set RNode to host-controlled mode

Use the -N option to set the device to host-controlled mode.

```sh
rnodeconf /dev/ttyUSB0 -N
```
