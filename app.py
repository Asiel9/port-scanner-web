from flask import Flask, render_template, request
import socket

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def scan():
    results = []
    error = None

    if request.method == 'POST':
        ip = request.form.get('ip')
        ports_input = request.form.get('ports')

        try:
            ports = parse_ports(ports_input)
            for port in ports:
                result = scan_port(ip, port)
                results.append(result)
        except Exception as e:
            error = str(e)

    return render_template('index.html', results=results, error=error)


def parse_ports(port_str):
    ports = set()
    parts = port_str.split(',')
    for part in parts:
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def scan_port(ip, port):
    result = {
        'port': port,
        'proto': 'TCP',
        'state': 'fermé',
        'banner': ''
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                result['state'] = 'ouvert'
                try:
                    s.sendall(b'Hello\r\n')
                    banner = s.recv(1024)
                    result['banner'] = banner.decode(errors='ignore').strip()
                except:
                    result['banner'] = ''
    except:
        pass
    return result


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
