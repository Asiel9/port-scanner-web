from scanner.core import verifie_addr, scanner_addr

if __name__ == "__main__":
    ip = verifie_addr()
    if ip:
        scanner_addr(ip)
