# Mini Packet Analyzer

A lightweight, command-line network packet analyzer built with Python. It captures live IPv4 traffic, manually decodes IPv4, TCP, and UDP headers from raw packet bytes, and provides packet inspection and filtering capabilities.

The project focuses on understanding network protocols at the byte level and implementing protocol-header parsing without relying on automatic packet-decoding libraries.

## Features

- **Live Packet Capture:** Capture inbound and outbound IPv4 traffic on Windows using PyDivert and WinDivert.
- **Manual Protocol Parsing:** Decode IPv4, TCP, and UDP headers directly from raw packet bytes.
- **Packet Summaries:** Display packet numbers, timestamps, source and destination IP addresses, protocols, ports, and packet lengths.
- **Protocol Filtering:** Filter captured traffic by TCP or UDP.
- **Address Filtering:** Filter packets by source and destination IP addresses.
- **Port Filtering:** Filter packets using source and destination port numbers.
- **Packet Inspection:** Examine individual packets and their IPv4 and transport-layer headers.
- **Payload Inspection:** Display packet payloads in hexadecimal and readable-text formats.
- **Input Validation:** Handle malformed packets, variable-length headers, fragmented packets, and empty payloads.

## Architecture

The application follows a modular architecture:

```text
             Network Traffic
                    |
                    v
          PyDivert / WinDivert
                    |
                    v
             Raw Packet Bytes
                    |
                    v
             packet_parser.py
                    |
           +--------+--------+
           |                 |
           v                 v
       IPv4 Parser      TCP/UDP Parser
           |                 |
           +--------+--------+
                    |
                    v
             Parsed Packets
                    |
             +------+------+
             |             |
             v             v
         filters.py    display.py
             |             |
             v             v
        Filtered       Packet Summary
        Packets        & Inspection
```

### Core Components

| Module | Responsibility |
|---|---|
| `main.py` | Application entry point, packet capture, and interactive CLI |
| `packet_parser.py` | Manual IPv4, TCP, and UDP header parsing |
| `filters.py` | Protocol, IP address, and port-based filtering |
| `display.py` | Packet summaries and detailed packet inspection |

## Technical Implementation

### Packet Capture

The application uses PyDivert, a Python interface to WinDivert, to capture raw IPv4 packets on Windows.

Capture is performed in sniffing mode, allowing the application to observe packets without intentionally blocking their normal processing.

### Manual Protocol Parsing

The core packet-analysis functionality is implemented directly in Python.

The parser uses:

- Byte offsets and slicing to access protocol fields.
- Bitwise operations to extract fields such as IPv4 Version, IHL, TCP Data Offset, and TCP flags.
- Python's `struct` module to decode multi-byte network fields.
- Python's `ipaddress` module to convert raw IP address bytes into readable addresses.

The implementation does not rely on Scapy, PyShark, or similar libraries for automatic protocol-header decoding.

### Packet Filtering

Captured packets can be filtered using multiple criteria:

- Protocol (TCP/UDP)
- Source IP address
- Destination IP address
- Source port
- Destination port

Multiple filters can be combined. A packet must satisfy all specified conditions to appear in the filtered results.

## Technology Stack

- **Language:** Python
- **Packet Capture:** PyDivert, WinDivert
- **Standard Libraries:** `struct`, `ipaddress`, `datetime`
- **Testing:** Python `unittest`
- **Platform:** Windows

## Installation

### Prerequisites

- Windows operating system
- Python 3.12 or a compatible Python 3 version
- Administrator privileges for packet capture
- WinDivert support

### 1. Clone the repository

```bash
git clone <repository-url>
cd Mini-Packet-Analyzer
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the environment

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

Ensure the required WinDivert driver/runtime support is available.

## Usage

Run the terminal or VS Code with Administrator privileges.

Start the application:

```bash
python main.py
```

The interactive menu provides options to:

1. Capture network packets.
2. Display captured packet summaries.
3. Filter packets using selected criteria.
4. Inspect individual packets.
5. Exit the application.

Generate network traffic using applications on your device, select the capture option, and press `Ctrl+C` to stop capturing and return to the menu.

## Testing

The project includes automated tests covering:

- IPv4 header parsing.
- TCP and UDP header parsing.
- Complete packet parsing.
- Malformed and edge-case packet handling.
- Packet filtering.

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

## Limitations

- Packet capture currently targets IPv4 traffic on Windows.
- Detailed transport-layer parsing supports TCP and UDP.
- Other IPv4 protocols can be identified in packet summaries but do not receive TCP/UDP-specific decoding.
- The application does not perform IP fragment reassembly.
- Packet capture requires appropriate system permissions and WinDivert support.

## Responsible Use

This tool is intended for learning, debugging, and analyzing network traffic on systems and networks you are authorized to monitor.

Captured packets may contain sensitive information. Handle packet data responsibly and avoid publishing captured payloads containing private information.

