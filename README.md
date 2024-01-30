# PySpy Scanner

## Introduction
PySpy Scanner is a network scanning tool designed for performing various network reconnaissance tasks such as SYN scan, TCP connect scan, ACK scan, banner grabbing, HTTP header evaluation, and operating system detection. 

**Note:** This project is currently a work in progress (WIP)

## Prerequisites
To run PySpy Scanner, you need to have the following installed on your system:
- Python 3.8.5
- pip 23.2.1

## Installation

First, clone the repository or download the source code. Then, navigate to the directory where the code is located and install the required dependencies using pip

```bash
pip install -r requirements.txt
```

## Usage

To use the PySpy Scanner, navigate to the directory containing the main.py file and use the following command syntax:

```bash
python3 main.py [options]
```

Where [options] include:

* -sS, --syn-scan : Perform a SYN scan on specified ports.
* -sT, --tcp-scan : Perform a TCP connect scan on specified ports.
* -sA, --ack-scan : Perform an ACK scan on specified ports.
* -b, --banner-grabbing : Perform banner grabbing on specified port.
* -he, --http-header : Perform evaluation of HTTP headers on specified port.
* -d, --os-detection : Detect operating system of the target device.
* -p, --ports : Comma-separated list of ports to scan.
* -dp, --default-ports : It enables PORTS by Default.
* -dd, --discover-devices : It discover available devices.

### Example Usage
To perform a TCP connect scan on ports 80 and 443 of a target IP address, use the following command:

```bash
python3 main.py -sT -p 80,443 192.168.1.1
```