import re
import sys
import csv

# TODO: Step 3
def get_log_file_path_from_cmd_line(paranumbers):
    if len(sys.argv) <= paranumbers:
        print(f"ERROR: There is no such parameter {paranumbers} available.")
        sys.exit(1)
    log_file_path = sys.argv[paranumbers]
    if not os.path.isfile(log_file_path):
        print(f"ERROR: This file {log_file_path} is not available.")
        sys.exit(1)
    return log_file_path

# TODO: Steps 4-7
def filter_log_by_regex(log_file_path, regex, casesensitive=False, print_summary=False, print_records=False):
    """Getting the list of record that is going to match with regex.

    Args:
        log_file (str): Show path of log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    flags = 0 if casesensitive else re.IGNORECASE
    patern = re.compile(regex, flags)
    matching_record = []
    with open(log_file_path, 'r') as file:
        for line in file:
            if patern.search(line):
                matching_record.append(line)
                if print_records:
                    print(line.strip())
    if print_summary:
        print(f"This log file have {len(matching_record)} regex that will match with records '{regex}'.")
    return matching_record

# TODO: Step 8
def tally_port_traffic(log_file_path):
    porttally = {}
    with open(log_file_path, 'r') as file:
        for line in file:
            matchs = re.search(r'DPT=(\d+)', line)
            if matchs:
                port = matchs.group(1)
                if port in porttally:
                    porttally[port] += 1
                else:
                    porttally[port] = 1
    return porttally

# TODO: Step 9
def generate_port_traffic_report(log_file_path, port_numbers):
    report_filename = f"destination_port_{port_numbers}_report.csv"
    with open(log_file_path, 'r') as file, open(report_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Date", "Time", "Source IP", "Destination IP", "Source Port", "Destination Port"])
        for line in file:
            if f"DPT={port_numbers}" in line:
                match = re.search(r'(\S+ \S+) (\S+) SRC=(\S+) DST=(\S+) .*SPT=(\S+) DPT=(\S+)', line)
                if match:
                    writer.writerow(match.groups())
    return

# TODO: Step 11
def generate_invalid_user_report(log_file_path):
    reportfile = "invalid_users.csv"
    with open(log_file_path, 'r') as file, open(reportfile, 'w', newline='') as csvfile:
        writers = csv.writer(csvfile)
        writers.writerow(["Date", "Time", "Username", "IP Address"])
        for line in file:
            if "WRONG USER" in line:
                matchs = re.search(r'(\S+ \S+) (\S+) Invalid user (\S+) from (\S+)', line)
                if matchs:
                    writers.writerow(matchs.groups())
                                    
# TODO: Step 12
def generate_source_ip_log(log_file_path, source_ip):
    outputfile = f"source_ip_{source_ip.replace('.', '_')}.log"
    with open(log_file_path, 'r') as file, open(outputfile, 'w') as output_file:
        for line in file:
            if f"SRC={source_ip}" in line:
                output_file.write(line)

def create_port_report(log_file_path, destination_port):
    reportfile = f"destination_port_{destination_port}_report.csv"
    with open(log_file_path, 'r') as file, open(reportfile, 'w', newline='') as csvfile:
        writers = csv.writer(csvfile)
        writers.writerow(["Date", "Time", "Source IP", "Destination IP", "Source Port", "Destination Port"])
        for line in file:
            if f"DPT={destination_port}" in line:
                match = re.search(r'(\S+ \S+) (\S+) SRC=(\S+) DST=(\S+) .*SPT=(\S+) DPT=(\S+)', line)
                if match:
                    writers.writerow(match.groups())

def create_invalid_user_report(log_file_path):
    reportfile= "invalid_users.csv"
    with open(log_file_path, 'r') as file, open(reportfile, 'w', newline='') as csvfile:
        writers = csv.writer(csvfile)
        writers.writerow(["Date", "Time", "Username", "IP Address"])
        for line in file:
            if "WRONG USERS" in line:
                match = re.search(r'(\S+ \S+) (\S+) Invalid user (\S+) from (\S+)', line)
                if match:
                    writers.writerow(match.groups())

def extract_source_ip_records(log_file_path, source_ip):
    output_file = f"source_ip_{source_ip.replace('.', '_')}.log"
    with open(log_file_path, 'r') as file, open(output_file, 'w') as output_file:
        for line in file:
            if f"SRC={source_ip}" in line:
                output_file.write(line)
from logs import (
    get_log_file_path_from_cmd_line,
    filter_log_by_regex,
    tally_port_traffic,
    generate_port_traffic_report,
    generate_invalid_user_report,
    generate_source_ip_log,
)

def main():
    log_file_path = get_log_file_path_from_cmd_line(1)
    
    filter_log_by_regex(log_file_path, 'SSHD', casesensitive=False, print_records=True, print_summary=True)
    filter_log_by_regex(log_file_path, 'INVALID USER', casesensitive=False, print_records=True, print_summary=True)
    filter_log_by_regex(log_file_path, 'INVALID USERS.*220.195.35.40', case_sensitive=False, print_records=True, print_summary=True)
    filter_log_by_regex(log_file_path, 'ERROR', casesensitive=False, print_records=True, print_summary=True)
    filter_log_by_regex(log_file_path, 'pam', casesensitive=False, print_records=True, print_summary=True)
    
    porttally = tally_port_traffic(log_file_path)
    for port, count in porttally.items():
        if count >= 100:
            generate_port_traffic_report(log_file_path, port)
    
    generate_invalid_user_report(log_file_path)
    generate_source_ip_log(log_file_path, '220.195.35.40')

if __name__ == '_main_':
    main()
