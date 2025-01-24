import nmap
import requests
import os

def detect_services(target_ip):
    scanner = nmap.PortScanner()
    services = {}
    try:
        scanner.scan(target_ip, '21-23', arguments='-sV')
        for host in scanner.all_hosts():
            for port in scanner[host]['tcp']:
                service = scanner[host]['tcp'][port]
                services[port] = {
                    'name': service['name'],
                    'version': service.get('version', 'N/A'),
                    'product': service.get('product', 'N/A')
                }
    except Exception as e:
        print(f"Error during Nmap scan: {e}")
    return services

def fetch_vulnerabilities(service_name, version):
    vulners_api_key = os.getenv("VULNERS_API_KEY")
    if not vulners_api_key:
        print("Error: Vulners API key not set.")
        return []

    endpoint = "https://vulners.com/api/v3/search/lucene/"
    query = f"{service_name} {version}"
    headers = {'Authorization': f"Bearer {vulners_api_key}"}

    try:
        response = requests.post(endpoint, json={"query": query}, headers=headers)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("data", {}).get("search", [])
        return vulnerabilities[:3]  # Return top 3 results
    except Exception as e:
        print(f"Error fetching vulnerabilities: {e}")
        return []

def display_results(services):
    for port, service in services.items():
        print(f"\n[Port {port}] {service['name']} - {service['product']} {service['version']}")
        vulnerabilities = fetch_vulnerabilities(service['name'], service['version'])
        if vulnerabilities:
            for vuln in vulnerabilities:
                print(f"- CVE: {vuln['id']}, Severity: {vuln.get('severity', 'N/A')}")
                print(f"  Description: {vuln.get('description', 'N/A')}")
        else:
            print("No vulnerabilities found.")

if __name__ == "__main__":
    target_ip = input("Enter the target IP: ")
    services = detect_services(target_ip)
    display_results(services)
