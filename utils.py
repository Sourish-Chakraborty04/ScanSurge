import csv
import json

def print_results(devices, ports=None, protocols=None):
    """Print scan results to console in a formatted table."""
    print("\nDiscovered Devices:")
    headers = ["IP Address", "MAC Address", "Hostname"] + ([f"Open Ports ({proto.upper()})" for proto in protocols or []] if ports else [])
    print(" ".join(f"{h:<20}" for h in headers))
    print("-" * (20 * len(headers)))
    for device in devices:
        row = [device["ip"], device["mac"], device["hostname"]]
        if ports and protocols:
            for proto in protocols:
                ports_str = ", ".join(f"{p['port']} ({p['service']})" for p in device["open_ports"].get(proto, []))
                row.append(ports_str or "None")
        print(" ".join(f"{v:<20}" for v in row))

def save_results(devices, filename, ports=None, protocols=None, format="csv"):
    """Save scan results to a file (CSV, JSON, or TXT)."""
    try:
        if format == "csv":
            fieldnames = ["ip", "mac", "hostname"] + ([f"open_ports_{proto}" for proto in protocols or []] if ports else [])
            with open(filename, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for device in devices:
                    row = {"ip": device["ip"], "mac": device["mac"], "hostname": device["hostname"]}
                    if ports and protocols:
                        for proto in protocols:
                            row[f"open_ports_{proto}"] = ", ".join(f"{p['port']} ({p['service']})" for p in device["open_ports"].get(proto, []))
                    writer.writerow(row)
        elif format == "json":
            with open(filename, "w") as f:
                json.dump(devices, f, indent=2)
        elif format == "txt":
            with open(filename, "w") as f:
                f.write("Discovered Devices:\n")
                headers = ["IP Address", "MAC Address", "Hostname"] + ([f"Open Ports ({proto.upper()})" for proto in protocols or []] if ports else [])
                f.write(" ".join(f"{h:<20}" for h in headers) + "\n")
                f.write("-" * (20 * len(headers)) + "\n")
                for device in devices:
                    row = [device["ip"], device["mac"], device["hostname"]]
                    if ports and protocols:
                        for proto in protocols:
                            ports_str = ", ".join(f"{p['port']} ({p['service']})" for p in device["open_ports"].get(proto, []))
                            row.append(ports_str or "None")
                    f.write(" ".join(f"{v:<20}" for v in row) + "\n")
        print(f"Results saved to {filename}")
    except Exception as e:
        print(f"Error saving results: {e}")