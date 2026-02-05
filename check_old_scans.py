#!/usr/bin/env python3
import json
import glob
import os

# Get oldest 5 scan files
scan_files = glob.glob('data/scans/*.json')
scan_files.sort()
oldest_files = scan_files[:5]

print('Checking oldest 5 scan files:')
for f in oldest_files:
    print(f'File: {os.path.basename(f)}')
    try:
        with open(f, 'r') as file:
            data = json.load(file)
            vulns = data.get('vulnerabilities', [])
            print(f'  URL: {data.get("url", "Unknown")}')
            print(f'  Vulnerabilities: {len(vulns)}')
            if vulns:
                print(f'  First vulnerability: {vulns[0].get("type", "Unknown")}')
    except Exception as e:
        print(f'  Error: {e}')
    print()
