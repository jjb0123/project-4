import json
import ssl
import socket
import re
import texttable as tt

#JSON loading function
def load_data(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def create_domain_table(data):
    table =tt.Texttable()
    headers =['Domain', 'IPv4 Addresses', 'IPv6 Addresses', 'HTTP Server', 'Insecure HTTP', 'Redirect to HTTPS', 'HSTS', 'TLS Versions', 'Root CA', 'RDNS Names', 'RTT Range', 'Geo Locations']
    table.header(headers)

    for domain, info in data.items():
        row=[
            domain,
            ', '.join(info['ipv4_addresses']),
            ', '.join(info['ipv6_addresses']),
            info['http_server'],
            info['insecure_http'],
            info['redirect_to_https'],
            info['hsts'],
            #info['hsts_redirect]
            ', '.join(info['tls_versions']),
            info['root_ca'],
            ', '.join(info['rdns_names']),
            ', '.join(map(str, info['rtt_range'])) if info['rtt_range'] else 'N/A',
            ', '.join(info['geo_locations'])
        ]
        table.add_row(row)

    return table.draw()

def create_rtt_table(data):
    table =tt.Texttable()
    table.header(['Domain', 'Min RTT (ms)', 'Max RTT (ms)'])
    sorted_data = sorted(data.items(), key=lambda x: x[1]['rtt_range'][0] if x[1]['rtt_range'] else float('inf'))

    for domain, info in sorted_data:
        if info['rtt_range']:
            table.add_row([domain, info['rtt_range'][0], info['rtt_range'][1]])

    return table.draw()

def count_occurrences(data, key):

    counts ={}
    for domain_info in data.values():
        value= domain_info[key]
        if value:
            counts[value]=counts.get(value, 0) + 1
            #counts[value]=counts.values[domain_info]
    return counts

def count_tls_versions(data):
    #hashmap to store versions
    tls_versions_count ={'TLSv1.0': 0, 'TLSv1.1': 0, 'TLSv1.2': 0, 'TLSv1.3': 0}
    for domain_info in data.values():
        for version in domain_info['tls_versions']:
            if version in tls_versions_count:
                tls_versions_count[version]+=1
    return tls_versions_count

def create_tls_support_table(data):
    table =tt.Texttable()
    table.header(['TLS Version', 'Support Percentage'])
    total_domains =len(data)
    tls_versions_count=count_tls_versions(data)

    for version, count in tls_versions_count.items():
        percentage=(count / total_domains) * 100
        table.add_row([version, f"{percentage:.2f}%"])

    return table.draw()


def create_count_table(counts, title):
    table=tt.Texttable()
    table.header([title, 'Occurrences'])
    for item, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
        table.add_row([item, count])
    return table.draw()

def generate_report(input_file, output_file):

    data=load_data(input_file)

    domain_report=create_domain_table(data)
    rtt_report=create_rtt_table(data)

    root_ca_counts = count_occurrences(data, 'root_ca')
    root_ca_report = create_count_table(root_ca_counts, 'Root CA')

    http_server_counts = count_occurrences(data, 'http_server')
    http_server_report = create_count_table(http_server_counts, 'HTTP Server')

    tls_support_report = create_tls_support_table(data)

    report = f"Domain Report:\n{domain_report}\n\nRTT Report:\n{rtt_report}\n\nRoot CA Report:\n{root_ca_report}\n\nHTTP Server Report:\n{http_server_report}\n\nTLS Support Report:\n{tls_support_report}"

    with open(output_file, 'w') as file:
        file.write(report)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("json: python3 report.py [outputtery.json] [output_file.txt]")
        sys.exit(1)

    input_json, output_txt = sys.argv[1], sys.argv[2]
    generate_report(input_json, output_txt)