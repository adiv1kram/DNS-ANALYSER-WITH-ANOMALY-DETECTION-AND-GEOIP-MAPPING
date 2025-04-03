import argparse
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from geoip2 import database
import geoip2.errors
import matplotlib.pyplot as plt
import folium
from collections import defaultdict
import sys


GEOIP_DB_PATH = 'GeoLite2-City.mmdb'  
ANOMALY_THRESHOLDS = {
    'nxdomain': 10,
    'unusual_qtype': 5,
    'high_traffic': 100,
    'long_subdomain': 50
}

class DNSAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.geoip_reader = database.Reader(GEOIP_DB_PATH)
        self.stats = {
            'nxdomain': defaultdict(int),
            'query_types': defaultdict(int),
            'src_ips': defaultdict(int),
            'domains': defaultdict(int),
            'geo_data': [],
            'response_codes': defaultdict(int),
            'suspicious_queries': []
        }

    def _geoip_lookup(self, ip):
   
        if ip.startswith(('192.168.', '10.', '172.16.', '127.')):
            #Here this functions assigns a  location for private IPs
            return {
                'city': 'Private Network',
                'country': 'Private Network',
                'lat': random.uniform(-90, 90),  
                'lon': random.uniform(-180, 180)  
            }

        try:
            response = self.geoip_reader.city(ip)
            return {
                'city': response.city.name if response.city.name else 'Unknown',
                'country': response.country.name if response.country.name else 'Unknown',
                'lat': response.location.latitude,
                'lon': response.location.longitude
            }
        except (geoip2.errors.AddressNotFoundError, AttributeError):
            return None

    def _process_dns_packet(self, packet):
        if packet.haslayer(DNS):
            ip_layer = packet.getlayer(IP)
            dns_layer = packet.getlayer(DNS)

            src_ip = ip_layer.src
            query = dns_layer.qd.qname.decode() if dns_layer.qd else None

            # This tracks basic statistics
            self.stats['src_ips'][src_ip] += 1
            self.stats['response_codes'][dns_layer.rcode] += 1

            if dns_layer.qr == 0:  # Query
                qtype = dns_layer.qd.qtype
                self.stats['query_types'][qtype] += 1
                if query:
                    self.stats['domains'][query] += 1

                    # it Detects long subdomains (possible DNS tunneling)
                    if len(query) > ANOMALY_THRESHOLDS['long_subdomain']:
                        self.stats['suspicious_queries'].append({
                            'type': 'long_subdomain',
                            'query': query,
                            'length': len(query),
                            'src_ip': src_ip
                        })

            elif dns_layer.qr == 1:  #this checks Response
                if dns_layer.rcode == 3:  #this checks NXDOMAIN
                    self.stats['nxdomain'][src_ip] += 1

                # this Checks for TXT records in responses
                if dns_layer.an and dns_layer.an.type == 16:  # TXT record
                    self.stats['suspicious_queries'].append({
                        'type': 'txt_response',
                        'query': query,
                        'src_ip': src_ip
                    })

           
            geo_info = self._geoip_lookup(src_ip)
            if geo_info:
                self.stats['geo_data'].append({
                    'ip': src_ip,
                    **geo_info
                })

    def _detect_anomalies(self):
        anomalies = []

        #this is  for excessive NXDOMAIN responses
        for ip, count in self.stats['nxdomain'].items():
            if count > ANOMALY_THRESHOLDS['nxdomain']:
                anomalies.append({
                    'type': 'excessive_nxdomain',
                    'ip': ip,
                    'count': count
                })

        # for Unusual query types (TXT=16, NULL=10, ANY=255)
        unusual_qtypes = {16: 'TXT', 10: 'NULL', 255: 'ANY'}
        for qtype, count in self.stats['query_types'].items():
            if qtype in unusual_qtypes and count > ANOMALY_THRESHOLDS['unusual_qtype']:
                anomalies.append({
                    'type': 'unusual_qtype',
                    'qtype': unusual_qtypes[qtype],
                    'count': count
                })

        # this is for High traffic sources
        for ip, count in self.stats['src_ips'].items():
            if count > ANOMALY_THRESHOLDS['high_traffic']:
                anomalies.append({
                    'type': 'high_traffic',
                    'ip': ip,
                    'count': count
                })

        # this is for Suspicious queries from processing
        anomalies.extend(self.stats['suspicious_queries'])

        return anomalies

    def analyze(self):
        try:
            packets = rdpcap(self.pcap_file)
            for packet in packets:
                self._process_dns_packet(packet)
        except Exception as e:
            print(f"Error processing PCAP file: {e}")
            sys.exit(1)

    def generate_report(self, output_file):
        anomalies = self._detect_anomalies()
        
        # Text Report
        with open(output_file, 'w') as f:
            f.write("DNS Analysis Report\n")
            f.write("===================\n\n")
            
            f.write("Top Statistics:\n")
            f.write(f"- Total DNS packets: {sum(self.stats['src_ips'].values())}\n")
            f.write(f"- Unique source IPs: {len(self.stats['src_ips'])}\n")
            f.write(f"- Unique domains queried: {len(self.stats['domains'])}\n\n")
            
            f.write("Anomalies Detected:\n")
            if not anomalies:
                f.write("No significant anomalies found\n")
            else:
                for anomaly in anomalies:
                    f.write(f"- {anomaly['type'].upper()}: ")
                    if 'ip' in anomaly:
                        f.write(f"IP {anomaly['ip']} ")
                    if 'count' in anomaly:
                        f.write(f"({anomaly['count']} occurrences)")
                    f.write("\n")
            
            # Generate GeoIP Map
            if self.stats['geo_data']:
                self._generate_geoip_map(output_file.replace('.txt', '_map.html'))

    def _generate_geoip_map(self, map_file):
        base_map = folium.Map(location=[0, 0], zoom_start=2)
        
        for entry in self.stats['geo_data']:
            popup_text = f"IP: {entry['ip']}<br>City: {entry['city']}<br>Country: {entry['country']}"
            folium.Marker(
                location=[entry['lat'], entry['lon']],
                popup=popup_text,
                icon=folium.Icon(color='red', icon='globe')
            ).add_to(base_map)
        
        base_map.save(map_file)
    
    def _process_dns_packet(self, packet):
        if packet.haslayer(DNS):
            
            src_ip = None

            # it checks if the packet has an IP layer
            if packet.haslayer(IP):
                ip_layer = packet.getlayer(IP)
                src_ip = ip_layer.src
            else:
                print("Skipping non-IP packet")
                return 

            dns_layer = packet.getlayer(DNS)
            query = dns_layer.qd.qname.decode() if dns_layer.qd else None

            # Log the packet details
            print(f"Processing DNS packet: Source IP = {src_ip}, Query = {query}")

            # Track basic statistics
            self.stats['src_ips'][src_ip] += 1
            self.stats['response_codes'][dns_layer.rcode] += 1

            if dns_layer.qr == 0:  # Query
                qtype = dns_layer.qd.qtype
                self.stats['query_types'][qtype] += 1
                if query:
                    self.stats['domains'][query] += 1

                    # Detect long subdomains (possible DNS tunneling)
                    if len(query) > ANOMALY_THRESHOLDS['long_subdomain']:
                        self.stats['suspicious_queries'].append({
                            'type': 'long_subdomain',
                            'query': query,
                            'length': len(query),
                            'src_ip': src_ip
                        })

            elif dns_layer.qr == 1:  # Response
                if dns_layer.rcode == 3:  # NXDOMAIN
                    self.stats['nxdomain'][src_ip] += 1

                # Check for TXT records in responses
                if dns_layer.an and dns_layer.an.type == 16:  # TXT record
                    self.stats['suspicious_queries'].append({
                        'type': 'txt_response',
                        'query': query,
                        'src_ip': src_ip
                    })

            # GeoIP lookup
            geo_info = self._geoip_lookup(src_ip)
            if geo_info:
                self.stats['geo_data'].append({
                    'ip': src_ip,
                    **geo_info
                })


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DNS Analyzer with Anomaly Detection')
    parser.add_argument('-f', '--file', required=True, help='PCAP file to analyze')
    parser.add_argument('-o', '--output', default='dns_report.txt', help='Output report file')
    args = parser.parse_args()

    analyzer = DNSAnalyzer(args.file)
    analyzer.analyze()
    analyzer.generate_report(args.output)
    print(f"Analysis complete. Report saved to {args.output}")

