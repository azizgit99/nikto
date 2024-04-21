import os
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from old.nikto_functions import parse_nikto_output, run_nikto

# GLOBAL VARIABLES
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
NIKTO_PATH = f"{BASE_DIR}/nikto/program/nikto.pl"
os.environ['LANG'] = 'English_United States.1252'
os.environ['LC_ALL'] = 'English_United States.1252'

app = Flask(__name__)

'''
WEB
'''
@app.route("/", methods=["GET","POST"])
def default():
    if request.method == "POST":
        command = ['perl', NIKTO_PATH]
        url = request.form.get('url')
        port = request.form.get('port', '')
        use_ssl = request.form.get('use_ssl', 'off')
        timeout = request.form.get('timeout', '')
        tuning = request.form.get('tuning', '')

        if url:
            command.extend(['-h', url])
        if port:
            command.extend(['-port', port])
        if use_ssl == 'on':
            command.append('-ssl')
        if timeout:
            command.extend(['-timeout', timeout])
        if tuning:
            command.extend(['-Tuning', tuning])
        output = run_nikto(command)
        output_json = parse_nikto_output(output)
        #save file

        return jsonify(output_json)
    return render_template('index.html')

'''
API (EXAMPLE):

URL
- http://127.0.0.1:5000/nikto-scan
HEADER
- Content-Type: application/json
BODY (RAW FORMAT)
- {
  "url": "https://owasp.org/"
}
'''
@app.route('/nikto-scan', methods=['POST'])
def nikto_scan():
    target_url = request.json.get('url')
    if not target_url:
        return jsonify({'error': 'URL parameter is required.'}), 400
    command = ['perl', NIKTO_PATH, '-h', target_url]
    output = run_nikto(command)
    results = parse_nikto_output(output)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
