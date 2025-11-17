import os
import sys
import argparse
from utils.file_loader import (load_file_content, identify_file_type, 
                                extract_strings_from_binary, is_archive, 
                                list_archive_contents)
from analyzers.script_analyzer import scan_script
from analyzers.macro_analyzer import scan_macros
from analyzers.exe_analyzer import scan_exe
from analyzers.vt_analyzer import scan_vt
from analyzers.android_analyzer import scan_android
from analyzers.universal_analyzer import (scan_universal, scan_binary_strings,
                                          scan_archive_contents, scan_pdf,
                                          scan_image_metadata, scan_config_file)
from utils.logger import log_result, print_colored
from analyzers.rules_loader import load_rules
from dotenv import load_dotenv

env_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(env_path)

RESULTS = []
STATS = {
    'total_files': 0,
    'scanned_files': 0,
    'infected_files': 0,
    'errors': 0,
    'skipped': 0
}


def get_filesize(filepath):
    size_in_bytes = os.path.getsize(filepath)
    size_in_kb = size_in_bytes / 1024
    return f"{size_in_kb:.2f}"


def scan_file(filepath, rules, verbose=False):
    """Enhanced file scanner that handles all file types"""
    detections = []
    STATS['total_files'] += 1
    
    if not os.path.isfile(filepath):
        print_colored(f"    [!] {filepath} is not a valid file", 'red')
        STATS['errors'] += 1
        return
    
    if verbose:
        print_colored(f"\n[+] Scanning: {filepath}", 'cyan')
    
    try:
        ftype = identify_file_type(filepath)
        file_size_kb = float(get_filesize(filepath))
        max_size_kb = int(os.getenv('MAX_SIZE', 100000))
        
        if verbose:
            print_colored(f"    [i] Type: {ftype} | Size: {file_size_kb:.2f} KB", 'cyan')
        
        # Check file size
        if file_size_kb > max_size_kb:
            print_colored(f"    [!] File too large: {file_size_kb:.2f} KB > {max_size_kb} KB", 'yellow')
            STATS['skipped'] += 1
            return
        
        # VirusTotal scan if enabled
        if os.getenv('VT_SCAN', 'false').lower() == 'true':
            if verbose:
                print_colored(f"    [*] Running VirusTotal scan...", 'cyan')
            vt_detections = scan_vt(filepath)
            if vt_detections:
                for tag, details in vt_detections:
                    if "error" in details.lower():
                        print_colored(f"    [!] {tag} - {details}", 'yellow')
                    else:
                        print_colored(f"    [!] {tag} - {details}", 'red')
                        detections.extend(vt_detections)
        
        # Load file content
        content = load_file_content(filepath)
        
        # Type-specific scanning
        if ftype == 'script' or ftype == 'text' or ftype == 'web':
            if verbose:
                print_colored(f"    [*] Scanning as script/text file...", 'cyan')
            detections.extend(scan_script(content, rules))
        
        elif ftype == 'office':
            if verbose:
                print_colored(f"    [*] Scanning for macros...", 'cyan')
            detections.extend(scan_macros(filepath, rules))
        
        elif ftype == 'exe':
            if verbose:
                print_colored(f"    [*] Scanning PE file...", 'cyan')
            detections.extend(scan_exe(filepath, rules))
            # Also extract and scan strings
            strings = extract_strings_from_binary(filepath)
            if strings:
                detections.extend(scan_binary_strings(strings, rules))
        
        elif ftype == 'archive':
            if verbose:
                print_colored(f"    [*] Scanning archive contents...", 'cyan')
            archive_files = list_archive_contents(filepath)
            if archive_files:
                detections.extend(scan_archive_contents(archive_files))
                if verbose:
                    print_colored(f"    [i] Archive contains {len(archive_files)} files", 'cyan')
        
        elif ftype == 'pdf':
            if verbose:
                print_colored(f"    [*] Scanning PDF file...", 'cyan')
            detections.extend(scan_pdf(filepath, rules))
        
        elif ftype == 'image':
            if verbose:
                print_colored(f"    [*] Scanning image metadata...", 'cyan')
            detections.extend(scan_image_metadata(filepath))
        
        elif ftype == 'config':
            if verbose:
                print_colored(f"    [*] Scanning configuration file...", 'cyan')
            detections.extend(scan_config_file(content, rules))
        
        elif ftype == 'android':
            if verbose:
                print_colored(f"    [*] Scanning Android file...", 'cyan')
            detections.extend(scan_android(filepath, rules))
        
        elif ftype == 'binary':
            if verbose:
                print_colored(f"    [*] Extracting and scanning binary strings...", 'cyan')
            strings = extract_strings_from_binary(filepath)
            if strings:
                detections.extend(scan_binary_strings(strings, rules))
        
        elif ftype == 'database':
            if verbose:
                print_colored(f"    [*] Scanning database file...", 'cyan')
            # Read as binary and extract strings
            strings = extract_strings_from_binary(filepath)
            if strings:
                detections.extend(scan_binary_strings(strings, rules))
        
        # Always run universal scanner as fallback/additional check
        else:
            if content and ftype not in ['exe', 'binary', 'archive', 'image']:
                universal_detections = scan_universal(content, rules, ftype)
                # Avoid duplicates
                for det in universal_detections:
                    if det not in detections:
                        detections.append(det)
        
        STATS['scanned_files'] += 1
        
        # Store results if threats found
        if detections:
            RESULTS.append((filepath, ftype, detections))
            STATS['infected_files'] += 1
            if verbose:
                print_colored(f"    [!] {len(detections)} threat(s) detected!", 'red')
        else:
            if verbose:
                print_colored(f"    [✓] Clean", 'green')
        
        # Log results
        log_result(filepath, ftype, detections)
        
    except Exception as e:
        print_colored(f"    [ERROR] {str(e)}", 'yellow')
        STATS['errors'] += 1
        log_result(filepath, 'error', [('scan_error', str(e))])


def scan_directory(target_path, rules, verbose=False, recursive=True):
    """Scan directory with all files"""
    print_colored(f"\n[+] Scanning directory: {target_path}", 'cyan')
    print_colored(f"    Recursive: {recursive}\n", 'cyan')
    
    if recursive:
        for root, dirs, files in os.walk(target_path):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                # Skip hidden files
                if file.startswith('.'):
                    continue
                    
                filepath = os.path.join(root, file)
                try:
                    scan_file(filepath, rules, verbose)
                except Exception as e:
                    print_colored(f"  [ERROR] {filepath}: {e}", 'yellow')
                    STATS['errors'] += 1
    else:
        # Non-recursive scan
        for file in os.listdir(target_path):
            filepath = os.path.join(target_path, file)
            if os.path.isfile(filepath) and not file.startswith('.'):
                try:
                    scan_file(filepath, rules, verbose)
                except Exception as e:
                    print_colored(f"  [ERROR] {filepath}: {e}", 'yellow')
                    STATS['errors'] += 1


def print_summary():
    """Print scan summary"""
    print_colored("\n" + "="*60, 'cyan')
    print_colored("SCAN SUMMARY", 'cyan')
    print_colored("="*60, 'cyan')
    print_colored(f"Total Files Found:    {STATS['total_files']}", 'cyan')
    print_colored(f"Files Scanned:        {STATS['scanned_files']}", 'green')
    print_colored(f"Infected Files:       {STATS['infected_files']}", 'red' if STATS['infected_files'] > 0 else 'green')
    print_colored(f"Errors:               {STATS['errors']}", 'yellow' if STATS['errors'] > 0 else 'green')
    print_colored(f"Skipped (too large):  {STATS['skipped']}", 'yellow')
    print_colored("="*60 + "\n", 'cyan')


def print_results():
    """Print detailed scan results"""
    if len(RESULTS) == 0:
        print_colored("[+] RESULT: All files are clean!", 'green')
    else:
        print_colored(f"[!] THREATS DETECTED IN {len(RESULTS)} FILE(S):", 'red')
        print_colored("="*60 + "\n", 'red')
        
        for filepath, ftype, detections in RESULTS:
            print_colored(f"[!] {filepath} [{ftype}]", 'red')
            
            # Group detections by category
            categories = {}
            for tag, pattern in detections:
                if tag not in categories:
                    categories[tag] = []
                categories[tag].append(pattern)
            
            for category, patterns in categories.items():
                print_colored(f"    [{category}] {len(patterns)} detection(s)", 'yellow')
                for i, pattern in enumerate(patterns[:5], 1):  # Show max 5 per category
                    # Truncate long patterns
                    if len(pattern) > 100:
                        pattern = pattern[:97] + "..."
                    print_colored(f"      {i}. {pattern}", 'red')
                if len(patterns) > 5:
                    print_colored(f"      ... and {len(patterns)-5} more", 'yellow')
            print()


def main():
    print_colored("""
╔═══════════════════════════════════════════════════════════╗
║                StealScan - Malware Scanner                ║
╚═══════════════════════════════════════════════════════════╝
    """, 'cyan')
    
    parser = argparse.ArgumentParser(
        description="StealScan - Malware Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Verbose output (show details for each file)")
    parser.add_argument("-nr", "--no-recursive", action="store_true",
                       help="Don't scan subdirectories")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Minimal output (only show threats)")
    
    args = parser.parse_args()
    
    # Load detection rules
    try:
        rules = load_rules()
        if not args.quiet:
            print_colored(f"[+] Loaded {sum(len(v) for v in rules.values() if isinstance(v, list))} detection rules\n", 'green')
    except Exception as e:
        print_colored(f"[!] Error loading rules: {e}", 'red')
        sys.exit(1)
    
    # Validate path
    if not os.path.exists(args.path):
        print_colored(f"[!] Path not found: {args.path}", 'red')
        sys.exit(1)
    
    # Start scanning
    verbose = args.verbose and not args.quiet
    
    if os.path.isdir(args.path):
        scan_directory(args.path, rules, verbose, not args.no_recursive)
    elif os.path.isfile(args.path):
        scan_file(args.path, rules, verbose)
    else:
        print_colored("[!] Invalid path", 'red')
        sys.exit(1)
    
    # Print results

    print_results()
    if not args.quiet:
        print_summary()


if __name__ == "__main__":
    main()