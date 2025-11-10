import re

def scan_script(file_content, rules):
    detections = []

    for tag, patterns in rules.items():
        for pattern in patterns:
            if re.search(pattern, file_content, re.IGNORECASE):
                detections.append((tag, pattern))

    return detections
