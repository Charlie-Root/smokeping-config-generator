import subprocess
import re
import geoip2.database
import socket

# Make sure to have the GeoIP databases in the same folder. Download them here:
# https://github.com/PrxyHunter/GeoLite2/releases/tag/2023.09.16

# List of high-traffic domains (you can fetch this from a data source)
high_traffic_domains = [
	"google.com"
	]

# Function to perform traceroute and return unique intermediate hops as IP addresses
def perform_traceroute(domain):
    try:
        result = subprocess.check_output(["traceroute", domain]).decode("utf-8")
        # Parse the traceroute output and extract hop IPs (ignoring asterisks)
        hop_pattern = re.compile(r'\((.*?)\)|(\d+\.\d+\.\d+\.\d+)')
        hops = [match.group(1) or match.group(2) for line in result.splitlines() for match in hop_pattern.finditer(line)]
        
        # Filter out asterisks and remove duplicates
        unique_hops = list(filter(lambda x: x != "*", set(hops)))
        return unique_hops
    except Exception as e:
        print(f"Error performing traceroute for {domain}: {e}")
        return []

# Function to get ASN information and provider's name for an IP address
def get_asn_info(ip_address):
    try:
        # Initialize the MaxMind GeoIP2 reader (you will need to download the GeoLite2 ASN database)
        reader = geoip2.database.Reader('GeoLite2-ASN.mmdb')
        response = reader.asn(ip_address)
        asn_number = response.autonomous_system_number
        asn_name = response.autonomous_system_organization
        return asn_number, asn_name
    except Exception as e:
        print(f"ASN information not found for {ip_address}. Skipping...")
        return None, None

# Function to format ASN names
def format_asn_name(asn_name):
    formatted_asn_name = re.sub(r'[^a-zA-Z0-9-]', '-', asn_name)
    return formatted_asn_name

# Dictionary to store the organized Smokeping configuration
smokeping_config = {}

# Generate Smokeping configuration and organize targets
for domain in high_traffic_domains:
    hops = perform_traceroute(domain)
    if hops:
        asn_to_ips = {}
        for hop in hops:
            if hop == "*":
                continue
            asn_number, asn_name = get_asn_info(hop)
            country = hop  # Default to IP address as country if not found in GeoIP2
            try:
                reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
                response = reader.country(hop)
                country = response.country.name.replace(" ", "")  # Remove spaces from country name
            except Exception as e:
                pass  # Ignore errors for country lookup

            # Get DNS name if available
            try:
                dns_name = socket.gethostbyaddr(hop)[0]
            except Exception as e:
                dns_name = None

            # Create the configuration entry (skip if ASN info not found)
            if asn_number:
                if asn_number not in asn_to_ips:
                    asn_to_ips[asn_number] = []

                formatted_hop = re.sub(r'[^a-zA-Z0-9-]', '', dns_name) if dns_name else hop.replace('.', '-')
                formatted_asn_name = format_asn_name(asn_name)
                asn_to_ips[asn_number].append({
                    "ip": hop,
                    "asn_name": asn_name,
                    "dns_name": dns_name,
                    "formatted_hop": formatted_hop,
                    "formatted_asn_name": formatted_asn_name
                })

        # Create the country entry if any ASN information is found
        if asn_to_ips:
            if country not in smokeping_config:
                smokeping_config[country] = {}

            for asn, ips in asn_to_ips.items():
                smokeping_config[country][f"AS-{ips[0]['formatted_asn_name']}"] = ips

# Function to format the Smokeping configuration as a string
def format_smokeping_config(config, indent=""):
    result = ""
    for country, asns in config.items():
        if country.isalpha():
            result += f"{indent}+ {country}\n"
            result += f"{indent}menu = {country}\n"
            for asn, ips in asns.items():
                result += f"{indent}  ++ {asn}\n"
                result += f"{indent}     menu = {asn}\n"
                for ip_info in ips:
                    result += f"{indent}   +++ {ip_info['formatted_hop']}\n"
                    result += f"{indent}       title = {ip_info['dns_name']} ({ip_info['ip']} {asn})\n"
                    result += f"{indent}       menu = {ip_info['ip']}\n"
                    result += f"{indent}       host = {ip_info['ip']}\n"
    return result

# Format the Smokeping configuration
formatted_config = format_smokeping_config(smokeping_config)

# Make sure to include this file in /etc/smokeping/config
# Specify the file path for the Smokeping configuration
output_file = '/etc/smokeping/config.d/auto_discovered_targets.conf'

# Save the configuration to the specified file
with open(output_file, 'w') as file:
    file.write(formatted_config)

print(f"Auto-discovered Smokeping targets updated and saved to {output_file}.")
