import json
import time
import requests
import subprocess
import re
import socket

def get_scan_time():
    return time.time()

def get_ipv4_addresses(domain, dns_resolvers_file='public_dns_resolvers.txt'):
    dns_resolvers = read_dns_resolvers(dns_resolvers_file)

    if not dns_resolvers:
        print("No DNS resolvers available.")
        return []

    ipv4_addresses = set()  # Using a set to avoid duplicates

    for resolver in dns_resolvers:
        try:
            result = subprocess.check_output(["nslookup", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            addresses = re.findall(r"Address: (\d+\.\d+\.\d+\.\d+)", result)
            ipv4_addresses.update(addresses)
        except subprocess.CalledProcessError as e:
            print(f"Error executing nslookup: {e}", file=sys.stderr)
            continue
        except subprocess.TimeoutExpired:
            print(f"nslookup command timed out for {domain} using resolver {resolver}", file=sys.stderr)
            continue

    return list(ipv4_addresses)

def read_dns_resolvers(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.", file=sys.stderr)
        return []

def get_ipv6_addresses(domain, dns_resolvers_file='public_dns_resolvers.txt'):
    dns_resolvers = read_dns_resolvers(dns_resolvers_file)

    if not dns_resolvers:
        print("No DNS resolvers available.")
        return []

    ipv6_addresses = set()

    for resolver in dns_resolvers:
        try:
            result = subprocess.check_output(["nslookup", "-type=AAAA", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            # Simplified regex to capture IPv6 addresses
            addresses = re.findall(r"([a-fA-F0-9:]{4,}::[a-fA-F0-9:]+)", result)
            if addresses:
                ipv6_addresses.update(addresses)
        except subprocess.CalledProcessError as e:
            print(f"Error executing nslookup for IPv6: {e.output.decode('utf-8')}", file=sys.stderr)
            continue
        except subprocess.TimeoutExpired:
            print(f"nslookup command for IPv6 timed out for {domain} using resolver {resolver}", file=sys.stderr)
            continue

    return list(ipv6_addresses)

def get_http_server(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        return response.headers.get('Server', None)
    except requests.RequestException:
        return None
    
def check_insecure_http(domain):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((domain, 80))
            return True
    except socket.error:
        return False
    return False

def check_redirect_to_https(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
        if response.history:
            final_url = response.url
            return final_url.startswith("https://")
        return False
    except requests.RequestException:
        return False

def scan_domains(input_file):
    results = {}
    with open(input_file, 'r') as file:
        for domain in file:
            domain = domain.strip()
            results[domain] = {
                "scan_time": get_scan_time(),
                "ipv4_addresses": get_ipv4_addresses(domain),
                "ipv6_addresses": get_ipv6_addresses(domain),
                "http_server": get_http_server(domain),
                "insecure_http": check_insecure_http(domain),
            }
            
    return results

def main(input_file, output_file):
    scan_results = scan_domains(input_file)
    with open(output_file, "w") as f:
        json.dump(scan_results, f, sort_keys=True, indent=4)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 scan.py [input_file.txt] [output_file.json]")
        sys.exit(1)

    input_file, output_file = sys.argv[1], sys.argv[2]
    main(input_file, output_file)
