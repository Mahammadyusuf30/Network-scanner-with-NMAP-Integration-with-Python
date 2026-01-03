import nmap, json
def advanced_scan(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-A -O -sV')
    results = {}
    for host in scanner.all_hosts():
        results[host] = {"state": scanner[host].state(), "protocols": {}}
        for proto in scanner[host].all_protocols():
            results[host]["protocols"][proto] = []
            for port in scanner[host][proto].keys():
                info = scanner[host][proto][port]
                results[host]["protocols"][proto].append({
                    "port": port,
                    "state": info['state'],
                    "service": info.get('name',''),
                    "product": info.get('product','')
                })
    with open("scan_report.json","w") as f: json.dump(results,f,indent=4)
if __name__ == '__main__':
    advanced_scan(input("Target: "))

import nmap
def basic_scan(target):
    scanner = nmap.PortScanner()
    print(f"Scanning {target} ...")
    scanner.scan(target, '1-1024', '-sV')
    for host in scanner.all_hosts():
        print(f"Host: {host}")
        print(f"State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                data = scanner[host][proto][port]
                print(f"Port: {port} State: {data['state']} Service: {data.get('name','')}")
if __name__ == '__main__':
    basic_scan(input("Target: "))


import nmap, csv
def scan_and_export(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, '1-1000', '-sV')
    with open("scan_results.csv","w",newline="") as f:
        w = csv.writer(f)
        w.writerow(["Host","Protocol","Port","State","Service"])
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port in scanner[host][proto].keys():
                    d = scanner[host][proto][port]
                    w.writerow([host, proto, port, d['state'], d.get('name','')])
if __name__ == '__main__':
    scan_and_export(input("Target: ")) 
