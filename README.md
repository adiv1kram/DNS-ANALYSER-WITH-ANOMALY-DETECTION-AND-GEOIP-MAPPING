# DNS-ANALYSER-WITH-ANOMALY-DETECTION-AND-GEOIP-MAPPING

## Overview
This project is a "DNS Analyzer" that processes **PCAP files** to detect anomalies in DNS traffic and map the geographical locations of source IPs. It provides insights into suspicious DNS activity and visualizes it using a world map.

## Features
- **Anomaly Detection**: Identifies unusual DNS queries, excessive NXDOMAIN responses, high traffic sources, and long subdomains.
- **GeoIP Mapping**: Determines the geographical locations of DNS queries.
- **TXT Record Inspection**: Detects suspicious TXT records in DNS responses.
- **Comprehensive Reporting**: Generates a detailed report summarizing anomalies and statistics.

## Installation

### Prerequisites
Ensure you have the following installed:
- Python 3.11.2
- Required libraries (install using the command below):
  ```bash
      pip install scapy geoip2 matplotlib folium
  ```
  - Scapy → For packet capture and analysis 
  ```bash
    pip install scapy
  ```
  - GeoIP2 → For GeoIP lookup of source IP addresses
  ```bash
  pip install scapy geoip2 matplotlib folium
  ```
  - Matplotlib → For plotting and data visualization
  ```bash
  pip install matplotlib
  ```
  - folium → For generating an interactive GeoIP map
  ```bash
    pip install folium
  ```
  - argparse → For handling command-line arguments (built into Python, no need to install separately)
  ```bash
    pip install argparse
  ```
  - sys → Provides system-specific parameters and functions (built into Python, no need to install separately)
  ```bash
    pip install sys
  ```
  - random → Generates random values for assigning private IP locations (built into Python, no need to install separately)
  ```bash
    pip install random
  ```
  

### GeoIP Database
Download and place the **GeoLite2-City.mmdb** database in the project directory. You can get it from [MaxMind](https://www.maxmind.com/en/geoip2-databases).
- I have uploaded the **GeoLite2-City.mmdb** file in the repository as well.

## Usage
Run the script with the following command:
```bash
python dns_analyzer.py -f <path_to_pcap> -o <output_report.txt>
```
Example:
```bash
python dns_analyzer.py -f your_own.pcapng -o dns_report.txt  
```

## Output
- **Text Report**: Summary of detected anomalies and statistics.
- **GeoIP Map**: HTML file visualizing the geographical locations of DNS queries.

## Repository Structure
```
📂 DNS-Analyzer
│── 📄 dns_analyzer.py                                                 # Main script
│── 📄 README.md                                                       # Documentation
│── 📄 requirements.txt                                                # Required dependencies that you need to install
│── 📄 HTML File                                                       # I have added an output file of mapped IP addresses
│── 📄 Anomalies detected                                              # Generated txt file with detected IPs from tfp_capture.pcapng
│── 📄 GeoLite2-City.mmdb                                              # GeoIP database
|── 📄 PPT file                                                        # PPT file for presentation
|── 📄 DNS Analyzer with Anomaly Detection.docx                        # Documentation file of the tool
```



## Contributor
- **Aditya Vikram Singh**

## Contact
For queries, reach out at psychh29@gmail.com
