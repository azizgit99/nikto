import os
import re
import json
import threading
import subprocess
from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

# Global dictionary to manage scans
scans = {}
scan_id_counter = 1

# Path to the Nikto script
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
NIKTO_PATH = f"{BASE_DIR}/nikto/program/nikto.pl"

def run_nikto(command):
    try:
        print("Executing command:", ' '.join(command))
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=3600)  # 1 hour timeout; adjust as needed
        return stdout
    except subprocess.TimeoutExpired:
        process.kill()
        return "Error: Nikto scan timeout expired."
    except Exception as e:
        return str(e)

def parse_nikto_output(nikto_output):
    results = {}

    # Extract target information
    target_ip_match = re.search(r'Target IP:\s*(\S+)', nikto_output)
    if target_ip_match:
        results['target_ip'] = target_ip_match.group(1)

    target_hostname_match = re.search(r'Target Hostname:\s*(\S+)', nikto_output)
    if target_hostname_match:
        results['target_hostname'] = target_hostname_match.group(1)

    target_port_match = re.search(r'Target Port:\s*(\d+)', nikto_output)
    if target_port_match:
        results['target_port'] = int(target_port_match.group(1))

    # Extract scan start and end time
    start_time_match = re.search(r'Start Time:\s*(\S+)', nikto_output)
    if start_time_match:
        results['start_time'] = start_time_match.group(1)

    end_time_match = re.search(r'End Time:\s*(\S+)', nikto_output)
    if end_time_match:
        results['end_time'] = end_time_match.group(1)

    # Extract server information
    server_match = re.search(r'Server:\s*(\S+)', nikto_output)
    if server_match:
        results['server'] = server_match.group(1)

    # Extract anti-clickjacking header information
    anti_clickjacking_match = re.search(r'The anti-clickjacking X-Frame-Options header (.+)', nikto_output)
    if anti_clickjacking_match:
        results['anti_clickjacking'] = anti_clickjacking_match.group(1)

    # Extract uncommon headers
    uncommon_headers = re.findall(r'Uncommon header \'(.+?)\' found, with contents: (.+)', nikto_output)
    if uncommon_headers:
        results['uncommon_headers'] = [{header[0]: header[1]} for header in uncommon_headers]

    # Extract CGI directories information
    cgi_directories_match = re.search(r'No CGI Directories found', nikto_output)
    results['cgi_directories_found'] = not bool(cgi_directories_match)

    # Extract number of items checked and reported
    items_checked_match = re.search(r'(\d+) items checked: (\d+) error\(s\) and (\d+) item\(s\) reported on remote host', nikto_output)
    if items_checked_match:
        results['items_checked'] = int(items_checked_match.group(1))
        results['errors'] = int(items_checked_match.group(2))
        results['items_reported'] = int(items_checked_match.group(3))

    # Extract number of hosts tested
    hosts_tested_match = re.search(r'(\d+) host\(s\) tested', nikto_output)
    if hosts_tested_match:
        results['hosts_tested'] = int(hosts_tested_match.group(1))

    return results

@app.route('/')
def index():
    return "Welcome to the Nikto Scanner API!"


@app.route('/startscan', methods=['POST'])
def start_scan():
    global scan_id_counter
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    options = data.get('options', {})
    scan_id = scan_id_counter
    scan_id_counter += 1

    command = ['perl', NIKTO_PATH, '-h', url] + parse_options(options)
    
    # Store the scan info
    scans[scan_id] = {
        'status': 'STARTED',
        'start_time': datetime.now().isoformat(),
        'url': url,
        'options': options,
        'output_file': f"{BASE_DIR}/results/scan_{scan_id}.json"
    }
    
    # Start the scan in a new thread
    thread = threading.Thread(target=perform_scan, args=(scan_id, command))
    thread.start()

    return jsonify({'message': 'Scan started', 'scan_id': scan_id})

def parse_options(options):
    # Convert options dictionary to Nikto command line arguments
    command_options = []
    for key, value in options.items():
        if key == "ssl":
            if value:
                command_options.append('-ssl')
        else:
            command_options.extend([f"-{key}", str(value)])
    return command_options

def perform_scan(scan_id, command):
    output = run_nikto(command)
    result = parse_nikto_output(output)
    
    # Save the output to a file
    with open(scans[scan_id]['output_file'], 'w') as f:
        json.dump(result, f)
    
    scans[scan_id]['status'] = 'COMPLETED'

@app.route('/scanstatus/<int:scan_id>', methods=['GET'])
def scan_status(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify({'scan_id': scan_id, 'status': scan['status'], 'results': scan.get('output_file')})

@app.route('/getresults/<int:scan_id>', methods=['GET'])
def get_results(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    if scan['status'] != 'COMPLETED':
        return jsonify({'status': scan['status'], 'error': 'Scan is not yet completed'}), 423

    with open(scan['output_file'], 'r') as f:
        results = json.load(f)

    return jsonify({'scan_id': scan_id, 'results': results})

if __name__ == '__main__':
    app.run(debug=True)
