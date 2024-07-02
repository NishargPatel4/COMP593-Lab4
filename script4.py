import re
import sys
import os
import csv

def get_log_file_path_from_cmd_line(paranumbers):
    if len(sys.argv) <= paranumbers:
        print(f"Error: No parameter {paranumbers} provided.")
        sys.exit(1)
    log_file_path = sys.argv[paranumbers]
    if not os.path.isfile(log_file_path):
        print(f"Error: The file {log_file_path} is not available.")
        sys.exit(1)
    return log_file_path

def filter_log_by_regex(log_file_path, regex, casesensitive = False, print_summary = False, print_records = False):
    flags = 0 if casesensitive else re.IGNORECASE
    patern = re.compile(regex, flags)
    matching_record = []
    captured_data = []
    with open(log_file_path, 'r') as file:
        for line in file:
            match = patern.search(line)
            if match:
                matching_record.append(line)
                captured_data.append(match.groups())
                if print_records:
                    print(line.strip())
    if print_summary:
        print(f"This logs file has {len(matching_record)} and regex will maych with record'{regex}'.")
    return matching_record, captured_data

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

def generate_port_traffic_report(log_file_path, port_numbers):
    reportfile = f"destination_port_{port_numbers}_report.csv"
    with open(log_file_path, 'r') as file, open(reportfile, 'w', newline='') as csvfile:
        writers = csv.writer(csvfile)
        writers.writerow(["Date", "Time", "Source IP", "Destination IP", "Source Port", "Destination Port"])
        for line in file:
            if f"DPT={port_numbers}" in line:
                match = re.search(r'(\S+ \S+) (\S+) SRC=(\S+) DST=(\S+) .*SPT=(\S+) DPT=(\S+)', line)
                if match:
                    writers.writerow(match.groups())

def generate_invalid_user_report(log_file_path):
    reportfile = "invalid_users.csv"
    with open(log_file_path, 'r') as file, open(reportfile, 'w', newline='') as csvfile:
        writers = csv.writer(csvfile)
        writers.writerow(["Date", "Time", "Username", "IP Address"])
        for line in file:
            if "WRONG USER" in line:
                match = re.search(r'(\S+ \S+) (\S+) Invalid user (\S+) from (\S+)', line)
                if match:
                    writers.writerow(match.groups())

def generate_source_ip_log(log_file_path, source_ip):
    outputfile= f"source_ip_{source_ip.replace('.', '_')}.log"
    with open(log_file_path)