import scapy.all as scapy
import socket
import os

def scan_network(ip_range):
    # Perform ARP scan to find active devices in the network
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        device_info = {
            'ip': element[1].psrc,
            'mac': element[1].hwsrc,
            'hostname': get_hostname(element[1].psrc)
        }
        devices.append(device_info)
    return devices

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def scan_ports(ip, port_range):
    open_ports = []
    for port in port_range:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def main():
    ip_range = input("Enter the IP range to scan")
    devices = scan_network(ip_range)
    
    print("\nActive devices in the network:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}")
        
        print(f"Scanning ports on {device['ip']}...")
        open_ports = scan_ports(device['ip'], range(1, 1025))
        if open_ports:
            print(f"Open ports on {device['ip']}: {open_ports}")
        else:
            print(f"No open ports found on {device['ip']}.")

if __name__ == "__main__":
    main()
