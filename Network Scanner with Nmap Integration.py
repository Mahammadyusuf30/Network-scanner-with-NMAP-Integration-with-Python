import nmap
import json
import time
import os
from pathlib import Path
from datetime import datetime

class Color:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    ORANGE = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

scanner = nmap.PortScanner()

VULN_RULES = {
    21: "FTP detected: Check for anonymous login & weak credentials",
    23: "Telnet open: CLEAR TEXT authentication — very insecure",
    80: "Web Server: Check for outdated Apache/Nginx versions",
    139: "Samba/NetBIOS: Potential SMB vulnerabilities",
    445: "SMBv1 exposure: Possible EternalBlue vulnerability",
    3306: "MySQL service: Ensure strong passwords and updated versions",
    3389: "RDP open: Protect against brute-force attacks",
    5900: "VNC open: Check if encryption is enabled"
}

def save_results_json(data, filename_prefix="scan_report"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    print(Color.GREEN + f"[+] JSON saved successfully → {filename}\n" + Color.END)

def basic_port_scan(target, start_port, end_port):
    output = []
    open_ports = 0

    output.append(f"[+] BASIC SCAN on {target} ({start_port}-{end_port})")

    try:
        scanner.scan(target, arguments=f"-p {start_port}-{end_port} -T4")
    except Exception as e:
        return f"[ERROR] {e}"

    if target not in scanner.all_hosts():
        return "[!] Target did not respond."

    scan_info = scanner[target]

    if "tcp" in scan_info:
        for port, data in scan_info['tcp'].items():
            state = data["state"]
            output.append(f"Port {port}/tcp is {state}")
            if state == "open":
                open_ports += 1

    output.append(f"\n[+] Scan Completed. Open Ports: {open_ports}\n")

    return "\n".join(output)

def version_scan(target, start_port, end_port):
    output = []
    open_ports = 0

    output.append(f"[+] SERVICE & VERSION SCAN on {target}")

    try:
        scanner.scan(target, arguments=f"-sV -p {start_port}-{end_port} -T4")
    except Exception as e:
        return f"[ERROR] {e}"

    if target not in scanner.all_hosts():
        return "[!] No response from target."

    for proto in scanner[target].all_protocols():
        for port in scanner[target][proto].keys():
            info = scanner[target][proto][port]
            state = info['state']
            service = info.get("name", "")
            product = info.get("product", "")
            version = info.get("version", "")

            if state == "open":
                open_ports += 1
                output.append(f"Port {port}/{proto} OPEN → {service} {product} {version}".strip())

    output.append(f"\n[+] Version scan completed. Open Ports: {open_ports}\n")

    return "\n".join(output)

def os_detection_scan(target):
    output = []
    output.append(f"[+] OS DETECTION SCAN on {target}")

    try:
        scanner.scan(target, arguments="-O -Pn -T4")
    except Exception as e:
        return f"[ERROR] {e}"

    if target not in scanner.all_hosts():
        return "[!] Target did not respond."

    osmatches = scanner[target].get("osmatch", [])

    if not osmatches:
        return "[!] OS could not be detected."

    output.append("\nPossible OS Matches:")
    for os_item in osmatches[:5]:
        output.append(f"- {os_item['name']} (accuracy {os_item['accuracy']}%)")

    return "\n".join(output)

def host_discovery(ip_range):
    output = []
    live_hosts = []

    output.append(f"[+] HOST DISCOVERY on {ip_range}")

    try:
        scanner.scan(hosts=ip_range, arguments="-sn -T4")
    except Exception as e:
        return f"[ERROR] {e}"

    for host in scanner.all_hosts():
        if scanner[host].state() == "up":
            live_hosts.append(host)

    if not live_hosts:
        output.append("\n[!] No live hosts found.")
    else:
        output.append("\nLive Hosts:")
        for host in live_hosts:
            output.append(f"- {host}")

    return "\n".join(output)

def save_output_to_desktop(content, filename_prefix):
    desktop = Path.home() / "Desktop"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    file_path = desktop / f"{filename_prefix}_{timestamp}.txt"

    try:
        with open(file_path, "w") as f:
            f.write(content)

        print(Color.GREEN + f"\n[+] TXT saved at Desktop → {file_path}" + Color.END)

    except Exception:
        print(Color.RED + "[!] Failed to save to desktop. Saving locally..." + Color.END)
        with open(f"{filename_prefix}.txt", "w") as f:
            f.write(content)

def main():
    print(Color.HEADER + "=== ADVANCED PYTHON NMAP TOOL ===" + Color.END)
    print(Color.ORANGE + "WARNING: Scan only systems you own or have permission for.\n" + Color.END)

    target = input("Enter IP for scanning (example: 192.168.1.10): ")

    print("""
Select Scan Type:
1. Fast Scan (Ports 21–80)
2. Deep Scan (Ports 1–1024)
3. Version Scan (Ports 1–1024)
4. OS Detection Scan
5. Host Discovery (Ping Sweep)
""")

    choice = input("Enter option (1-5): ")

    if choice == "1":
        output = basic_port_scan(target, 21, 80)
        save_output_to_desktop(output, "FastScan")
        save_results_json({"target": target, "output": output})

    elif choice == "2":
        output = basic_port_scan(target, 1, 1024)
        save_output_to_desktop(output, "DeepScan")
        save_results_json({"target": target, "output": output})

    elif choice == "3":
        output = version_scan(target, 1, 1024)
        save_output_to_desktop(output, "VersionScan")
        save_results_json({"target": target, "output": output})

    elif choice == "4":
        output = os_detection_scan(target)
        save_output_to_desktop(output, "OSDetection")
        save_results_json({"target": target, "output": output})

    elif choice == "5":
        ip_range = input("Enter IP range (192.168.1.1-254): ")
        output = host_discovery(ip_range)
        save_output_to_desktop(output, "HostDiscovery")
        save_results_json({"range": ip_range, "output": output})

    else:
        print(Color.RED + "Invalid option!" + Color.END)

if __name__ == "__main__":
    main()
