import os
import re
import sys
import argparse

SENSITIVE_PATTERNS = [
    (r'(?i)api[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?', "Potential API Key"),
    (r'(?i)password\s*[:=]\s*["\']?[^"\'\s]{8,}["\']?', "Hardcoded Password"),
    (r'(?i)secret\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?', "Potential Secret Token"),
]

def scan_file(filepath):
    issues = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for idx, line in enumerate(f, 1):
                for pattern, desc in SENSITIVE_PATTERNS:
                    if re.search(pattern, line):
                        issues.append((idx, desc))
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    return issues

def scan_directory(target_dir):
    print(f"Scanning target directory: {target_dir}")
    total_issues = 0
    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith(('.yml', '.yaml', '.json', '.env', '.conf')):
                full_path = os.path.join(root, file)
                issues = scan_file(full_path)
                if issues:
                    print(f"\n[ALERT] Security issues in {full_path}:")
                    for line_no, desc in issues:
                        print(f"  Line {line_no}: {desc}")
                        total_issues += 1
    return total_issues

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit infrastructure configuration files.")
    parser.add_argument("--path", default=".", help="Directory to scan")
    args = parser.parse_args()

    found = scan_directory(args.path)
    print(f"\nAudit complete. Found {found} potential issue(s).")
    sys.exit(1 if found > 0 else 0)
