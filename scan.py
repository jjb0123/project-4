import json
import time
import requests
import subprocess
import re
import socket
import ssl
import maxminddb
from OpenSSL import crypto

#5.1

def get_scan_time():
    return time.time()

def read_dns_resolvers(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error- File {file_path} not found.", file=sys.stderr)
        return []

#5.2
def get_ipv4_addresses(domain, dns_resolvers_file='public_dns_resolvers.txt'):
    dns_resolvers = read_dns_resolvers(dns_resolvers_file)

    if not dns_resolvers:
        print("No resolvers available")
        return []

    ipv4_addresses = set()

    for resolver in dns_resolvers:
        try:
            result = subprocess.check_output(["nslookup", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            addresses = re.findall(r"Address: (\d+\.\d+\.\d+\.\d+)", result)
            ipv4_addresses.update(addresses)
        except subprocess.CalledProcessError as e:
            print(f"error executing nslookup: {e}", file=sys.stderr)
            continue
        except subprocess.TimeoutExpired:
            print(f"nslookup command timed out for {domain} using resolver {resolver}", file=sys.stderr)
            continue

    return list(ipv4_addresses)

#5.3
def get_ipv6_addresses(domain, dns_resolvers_file='public_dns_resolvers.txt'):
    dns_resolvers = read_dns_resolvers(dns_resolvers_file)

    if not dns_resolvers:
        print("No resolvers available")
        return []

    ipv6_addresses =set()

    for resolver in dns_resolvers:
        try:
            result =subprocess.check_output(["nslookup", "-type=AAAA", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            addresses =re.findall(r"([a-fA-F0-9:]{4,}::[a-fA-F0-9:]+)", result)
            ipv6_addresses.update(addresses)
        except subprocess.CalledProcessError as e:
            print(f"Error executing nslookup for IPv6: {e.output.decode('utf-8')}", file=sys.stderr)
            continue
        except subprocess.TimeoutExpired:
            print(f"nslookup command for IPv6 timed out for {domain} using resolver {resolver}", file=sys.stderr)
            continue

    return list(ipv6_addresses)

#5.4
def get_http_server(domain):
    try:
        response= requests.get(f"http://{domain}", timeout=5)
        return response.headers.get('Server', None)
    except requests.RequestException:
        return None

#5.5
def check_insecure_http(domain):
    try:
        response=requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
        if response.status_code==200:
            return True
        if response.url.startswith("http://"):
            return True
        return False
    except requests.RequestException:
        return False

#5.6
def check_redirect_to_https(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
        if response.history:
            final_url=response.url
            #check redirect with final URL
            return final_url.startswith("https://")
        return False
    except requests.RequestException:
        return False
#5.7
def check_hsts(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
        #print(response.headers)
        return 'strict-transport-security' in response.headers
    except requests.RequestException:
        return False

#5.8
def get_supported_tls_versions(domain):


    tls_versions = {
        'TLSv1.0':ssl.PROTOCOL_TLSv1,
        'TLSv1.1':ssl.PROTOCOL_TLSv1_1,
        'TLSv1.2':ssl.PROTOCOL_TLSv1_2,
        'TLSv1.3':ssl.PROTOCOL_TLS,  
    }


    supported_versions=[]

    for version, protocol in tls_versions.items():
        try:
            context=ssl.SSLContext(protocol)
            #context=ssl.SSLContext(version)
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain):
                    supported_versions.append(version)
        except (ssl.SSLError, OSError):
            continue

    return supported_versions

#5.9
def get_root_ca(domain):
    try:
        context=ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:
                cert_bin=ssl_sock.getpeercert(binary_form=True)
                x509=crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                issuer=x509.get_issuer()
                #print(issuer)
                return issuer.organizationName
    except Exception:
        return None
#5.10
def get_rdns_names(ipv4_addresses):
    rdns_names=[]
    for ip in ipv4_addresses:
        try:
            name, _, _ =socket.gethostbyaddr(ip)
            rdns_names.append(name)
        except socket.herror:  # no reverse DNS record found innit
            continue
    return rdns_names

#5.11
def measure_rtt(ipv4_addresses):
    min_rtt= float('inf')
    max_rtt= 0

    for ip in ipv4_addresses:
        start_time =time.time()
        try:
            with socket.create_connection((ip, 443), timeout=5) as s:
                pass
        except (socket.timeout, socket.error):
            continue
        end_time =time.time()

        rtt = (end_time - start_time)*1000  
        min_rtt =min(min_rtt, rtt)
        max_rtt =max(max_rtt, rtt)

    if min_rtt ==float('inf') or max_rtt== 0:
        return None 

    return [min_rtt, max_rtt]
#5.12
def get_geo_locations(ipv4_addresses, db_path='GeoLite2-City.mmdb'):
    locations = set()
    with maxminddb.open_database(db_path) as reader:
        for ip in ipv4_addresses:
            #tryexcept to catch mddb errors
            try:
                response = reader.get(ip)
                if response:
                    #find different parts of the geolocation
                    city = response.get('city', {}).get('names', {}).get('en', '')
                    province = response.get('subdivisions', [{}])[0].get('names', {}).get('en', '')
                    country = response.get('country', {}).get('names', {}).get('en', '')
                    location = f"{city}, {province}, {country}".strip(', ')
                    locations.add(location)
            except maxminddb.errors.InvalidDatabaseError:
                continue

    return list(locations)


# return all doamins
def scan_domains(input_file):
    results = {}
    with open(input_file, 'r') as file:
        for domain in file:
            domain = domain.strip()
            ipv4_addresses = get_ipv4_addresses(domain)
            results[domain] = {
                "scan_time": get_scan_time(),
                "ipv4_addresses": ipv4_addresses,
                "ipv6_addresses": get_ipv6_addresses(domain),
                "http_server": get_http_server(domain),
                "insecure_http": check_insecure_http(domain),
                "redirect_to_https": check_redirect_to_https(domain),
                "hsts": check_hsts(domain),
                "tls_versions": get_supported_tls_versions(domain),
                "root_ca": get_root_ca(domain),
                "rdns_names": get_rdns_names(ipv4_addresses),
                "rtt_range": measure_rtt(ipv4_addresses),
                "geo_locations": get_geo_locations(ipv4_addresses),
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
