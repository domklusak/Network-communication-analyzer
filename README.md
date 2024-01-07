Based on your project documentation, here's a suggested README file for your GitHub repository:

---

# Network Communication Analyzer

## Overview
This project is a Python-based Network Communication Analyzer that processes `.pcap` files to analyze network communications. The analyzer identifies and aggregates communication pairs and provides comprehensive insights into network interactions.

## Features
- **Packet Analysis**: Processes `.pcap` files to extract detailed information about each packet.
- **Communication Pairing**: Identifies and groups communication pairs in the network data.
- **Output in YAML**: Generates a detailed `.yaml` file with all communication analyses.

## Requirements
- Python 3.x
- Libraries:
  - `binascii`: For converting binary data into ASCII.
  - `scapy.utils`: Used for various utilities in handling packets.
  - `bitstring`: For manipulating binary data more easily.
  - `ruamel.yaml.scalarstring`: To handle YAML serialization with specific scalar string types.

Ensure you have these libraries installed to use the Network Communication Analyzer effectively.

## Usage
To use the analyzer, run the script with the `.pcap` file as an input:

```
python [your_script_name].py <input_file.pcap>
```

This command will generate a `.yaml` output file containing the analyzed communication data.

## Output
The output `.yaml` file includes detailed information about network communications:
- Frame details in hexadecimal format
- MAC addresses
- IP addresses and protocols
- Specific communication details for various protocols
