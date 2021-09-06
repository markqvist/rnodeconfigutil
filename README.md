# RNode Configuration Utility

## Introduction

Configure, flash, backup and upgrade your [RNode](https://unsigned.io/projects/rnode/) with this handy utility. The only required option is the serial port the device is attached to. To show basic device info, use the -i option.

RNode can operate in two modes, host-controlled (default) and TNC mode:

- When RNode is in host-controlled mode, it will stay in standby when powered on, until the host specifies frequency, bandwidth, transmit power and other required parameters. This mode can be enabled by using the -N option of this utility.

- When RNode is in TNC mode, it will configure itself on powerup and enable the radio immediately. This mode can be enabled by using the -T option of this utility (the utility will guide you through the settings if you don't specify them directly).

For a complete description of RNodes capabilities, documentation and more, please refer to the [RNode repository](https://github.com/markqvist/RNode_Firmware).

```
usage: rnodeconf.py [-h] [-i] [-T] [-N] [-b] [-d] [-f] [-r] [-u] [-k] [-p]
                    [--model model] [--hwrev revision] [--freq Hz] [--bw Hz]
                    [--txp dBm] [--sf factor] [--cr rate]
                    [port]

RNode Configuration and firmware utility. This program allows you to change
various settings and startup modes of RNode. It can also flash and update the
firmware, and manage device EEPROM.

positional arguments:
  port              serial port where RNode is attached

optional arguments:
  -h, --help        show this help message and exit
  -i, --info        Show device info
  -T, --tnc         Switch device to TNC mode
  -N, --normal      Switch device to normal mode
  -b, --backup      Backup EEPROM to file
  -d, --dump        Dump EEPROM to console
  -f, --flash       Flash firmware and bootstrap EEPROM
  -r, --rom         Bootstrap EEPROM without flashing firmware
  -u, --update      Update firmware
  -k, --key         Generate a new signing key and exit
  -p, --public      Display public part of signing key
  --model model     Model code for EEPROM bootstrap
  --hwrev revision  Hardware revision EEPROM bootstrap
  --freq Hz         Frequency in Hz for TNC mode
  --bw Hz           Bandwidth in Hz for TNC mode
  --txp dBm         TX power in dBm for TNC mode
  --sf factor       Spreading factor for TNC mode
  --cr rate         Coding rate for TNC mode
```

## Installation

The easiest way to install the configuration utility is with pip:

```sh
# If you don't already have pip installed
sudo apt install python3-pip

# Install rnodeconf with pip
pip3 install rnodeconf

# Run rnodeconf
rnodeconf --help
```

On some operating systems, programs installed by pip cannot be run simply by typing their name. If you get a __command not found__ error, you will have to add the pip install directory to your PATH variable. The best way to do this is to edit the ".profile" file in your home directory and add the following lines at the bottom of the file:

```sh
# Include locally installed programs in path
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
```

If you want to use the utility for firmware updating or flashing, you will also need avrdude:

```sh
sudo apt install avrdude
```

You can also clone or download this repository, place it wherever you'd like and run rnodeconf from there:

```sh
# Clone repository
git clone https://github.com/markqvist/rnodeconfigutil.git

# Move into folder
cd rnodeconfigutil

# Set executable permission on rnodeconf
chmod a+x rnodeconf/rnodeconf.py

# Symlink executable to main directory
ln -s rnodeconf/rnodeconf.py rnodeconfig

# Run rnodeconf
./rnodeconfig --help
```

## Dependencies

The config utility requires Python 3, pyserial and cryptography.io. To install:

```sh
# Install dependencies for rnodeconf
sudo pip3 install pyserial cryptography
```

## Examples

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
