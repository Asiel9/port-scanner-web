import nmap
import ipaddress
from datetime import datetime
import socket


def banner_grab(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((ip, port))
            if port in [80, 8080, 8000]:
                http_request = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
                s.send(http_request.encode())
            banner = s.recv(1024).decode(errors="ignore")
            return banner.strip() if banner else "Aucune réponse"
    except:
        return None


def verifie_addr():
    try:
        ip = input("Entrez une adresse IP à scanner : ")
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        print("Adresse IP invalide.")
        return None


def scanner_addr(ip):
    try:
        port_range = input("Plage de ports (ex : 1-1024 ou 80,443,8080) : ")
        scanner = nmap.PortScanner()
        scanner.scan(ip, port_range)

        date_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        output_lines = [
            "-----",
            f"Date du scan : {date_scan}",
            f"Adresse IP : {ip}",
            f"Plage de ports : {port_range}\n"
        ]

        print(f"\nScan de {ip} lancé...\n")

        for host in scanner.all_hosts():
            state = scanner[host].state()
            output_lines.append(f"État de l'hôte : {state}")
            print(f"État de l'hôte : {state}")

            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    state = scanner[host][proto][port]['state']
                    line = f"Port {port}/{proto} : {state}"
                    print(line)
                    output_lines.append(line)

                    if state == "open":
                        banner = banner_grab(ip, port)
                        if banner:
                            print(f"  ↪ Bannière : {banner}")
                            output_lines.append(f"  ↪ Bannière : {banner}")

        filename = "resultats_scans.txt"
        with open(filename, "a", encoding="utf-8") as f:
            f.write("\n".join(output_lines) + "\n")

        print(f"\nRésultats ajoutés à : {filename}")

    except Exception as e:
        print("Erreur de scan :", e)


ip = verifie_addr()
if ip:
    scanner_addr(ip)
