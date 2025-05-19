from flask import Blueprint, render_template, request
from scanner.core import scanner_addr

main = Blueprint('main', __name__)


@main.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        ip = request.form['ip']
        ports = request.form['ports']
        results = scanner_addr(ip, ports)
        return render_template('index.html', results=results)
    return render_template('index.html')
