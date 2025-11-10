import os
import sys
import argparse
from utils.file_loader import load_file_content, identify_file_type
from analyzers.script_analyzer import scan_script
from analyzers.macro_analyzer import scan_macros
from analyzers.exe_analyzer import scan_exe
from analyzers.vt_analyzer import scan_vt
from utils.logger import log_result, print_colored
from analyzers.rules_loader import load_rules
from dotenv import load_dotenv
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
load_dotenv()

RESULTS = []


def get_filesize(filepath):
    size_in_bytes = os.path.getsize(filepath)
    size_in_kb = size_in_bytes / 1024
    return f"{size_in_kb:.2f}"

def scan_file(filepath, rules):
    detections = []
    if not os.path.isfile(filepath):
        print_colored(f"    [!] {filepath} is not a valid file", 'red')
        return
    
    print_colored(f"[+] Scanning: {filepath}", 'cyan')
    ftype = identify_file_type(filepath)

    if float(get_filesize(filepath)) > int(os.getenv('MAX_SIZE')):
        print_colored(f"    [!] Exceeds the maximum size limit {get_filesize(filepath)} KB > {os.getenv('MAX_SIZE')} KB", 'red')
    else:
        print_colored(f"    [!] Size: {get_filesize(filepath)} KB", 'green')
        content = load_file_content(filepath)
        if os.getenv('VT_SCAN').lower() == 'true':
            vt_detections = scan_vt(filepath)
            if vt_detections:
                for tag, details in vt_detections:
                    if "error" in details.lower():
                        print_colored(f"    [!] {tag} - {details}", 'red')
                        sys.exit(0)
                    print_colored(f"  [!] {tag} - {details}", 'red')
                log_result(filepath, ftype, vt_detections)

        if ftype == 'script':
            detections = scan_script(content, rules)
        elif ftype == 'office':
            detections = scan_macros(filepath,rules)
        elif ftype == 'exe':
            detections = scan_exe(filepath, rules)

        if detections:
            RESULTS.append((filepath, detections))

    log_result(filepath, ftype, detections)


def scan_directory(target_path, rules):
    for root, _, files in os.walk(target_path):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                scan_file(filepath, rules)
            except Exception as e:
                print_colored(f"  [ERROR] {e}", 'yellow')


def main():
    parser = argparse.ArgumentParser(description="StealScan - Stealer, Logger, and Malicious Files Scanner for windows")
    parser.add_argument("path", help="File or directory to scan")
    args = parser.parse_args()

    rules = load_rules()

    if os.path.isdir(args.path):
        scan_directory(args.path, rules)
    elif os.path.isfile(args.path):
        scan_file(args.path, rules)
    else:
        print_colored("[!] Invalid path", 'red')

    if len(RESULTS) == 0:
        print_colored("\n[+] Scan Results:", 'green')
        print_colored("    [+] All Clean", 'green')
    else:
        print_colored("\n[+] Scan Results:", 'green')
        for path,detections in RESULTS:
            if detections != 0:
                print_colored(f"[+] {path}", 'green')
                for tag, pattern in detections:
                    print_colored(f"    [!] {tag}: {pattern}", 'red')


if __name__ == "__main__":
    main()
