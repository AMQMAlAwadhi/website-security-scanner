#!/usr/bin/env python3
"""Simple syntax validation script"""
import ast
import sys

files_to_check = [
    'src/website_security_scanner/utils/evidence_verifier.py',
    'src/website_security_scanner/analyzers/common_web_checks.py',
    'src/website_security_scanner/utils/platform_detector.py',
    'src/website_security_scanner/main.py',
    'src/website_security_scanner/analyzers/advanced_checks.py',
    'src/website_security_scanner/report_generator.py',
    'src/website_security_scanner/cli/cli.py',
]

errors = []
for filepath in files_to_check:
    try:
        with open(filepath, 'r') as f:
            source = f.read()
        ast.parse(source)
        print(f"✓ {filepath}")
    except SyntaxError as e:
        errors.append(f"✗ {filepath}: {e}")
        print(f"✗ {filepath}: {e}")
    except Exception as e:
        errors.append(f"✗ {filepath}: {e}")
        print(f"✗ {filepath}: {e}")

if errors:
    print(f"\n{len(errors)} file(s) have errors")
    sys.exit(1)
else:
    print("\nAll files passed syntax check")
    sys.exit(0)
