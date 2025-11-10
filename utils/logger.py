from datetime import datetime
from colorama import init, Fore

init(autoreset=True)

def log_result(filepath, filetype, detections):
    with open('scan_log.txt', 'a') as log:
        log.write(f"{datetime.now()} - {filepath} [{filetype}]\n")
        if detections:
            for tag, pattern in detections:
                log.write(f"  [+] DETECTED: {tag} - {pattern}\n")
        else:
            log.write("  [+] CLEAN\n")
        log.write("\n")

def print_colored(text, level):
    color = {
        'red': Fore.RED,
        'green': Fore.GREEN,
        'yellow': Fore.YELLOW,
        'cyan': Fore.CYAN
    }.get(level, Fore.WHITE)
    print(color + text)
