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
- Python 3.x
- Required libraries (install using the command below):
  ```bash
  pip install scapy geoip2 matplotlib folium
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
python dns_analyzer.py -f example.pcap -o dns_report.txt
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
