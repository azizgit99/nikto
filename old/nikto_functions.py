import re
import subprocess

'''
runs nikto scan
'''
def run_nikto(command):
    try:
        print("Executing command:", ' '.join(command))
        nikto_output = subprocess.run(command, capture_output=True, text=True, check=True)
        return nikto_output  # Return the standard output if successful
    except subprocess.CalledProcessError as e:
        # Return both stdout and stderr to get more context on the error
        # return {"stdout": e.stdout, "stderr": e.stderr, "error": str(e)}
        return e.stdout

'''
change output to JSON format
'''
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