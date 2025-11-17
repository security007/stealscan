import re
import zipfile
from analyzers import android_analyzer


def scan_universal(content, rules, file_type='unknown'):
    """
    Universal scanner that works on any file content
    Scans for all suspicious patterns regardless of file type
    """
    detections = []
    
    if content is None or len(content) == 0:
        return detections
    
    # Convert bytes to string if needed
    if isinstance(content, bytes):
        try:
            content = content.decode('utf-8', errors='ignore')
        except:
            content = str(content)
    
    # Scan all rule categories
    all_patterns = {}
    
    # Combine all rules into one dictionary
    for category in rules:
        if isinstance(rules[category], list):
            all_patterns[category] = rules[category]
    
    # Scan for each pattern
    for category, patterns in all_patterns.items():
        for pattern in patterns:
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Get context around the match
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 30)
                    context = content[start:end].replace('\n', ' ').replace('\r', '')
                    
                    detection_info = f"{pattern} | Context: ...{context}..."
                    detections.append((category, detection_info))
                    
                    # Limit detections per pattern to avoid spam
                    break
            except re.error:
                # If regex pattern is invalid, try simple string search
                if pattern.lower() in content.lower():
                    # Find first occurrence
                    idx = content.lower().find(pattern.lower())
                    start = max(0, idx - 30)
                    end = min(len(content), idx + len(pattern) + 30)
                    context = content[start:end].replace('\n', ' ').replace('\r', '')
                    
                    detection_info = f"{pattern} | Context: ...{context}..."
                    detections.append((category, detection_info))
            except Exception:
                continue
    
    return detections


def scan_binary_strings(strings_content, rules):
    """
    Scan extracted strings from binary files
    """
    return scan_universal(strings_content, rules, 'binary')


def scan_archive_contents(archive_files, suspicious_extensions=None):
    """
    Check archive contents for suspicious files
    """
    detections = []
    
    if suspicious_extensions is None:
        suspicious_extensions = ['.exe', '.dll', '.scr', '.bat', '.cmd', 
                                '.ps1', '.vbs', '.js', '.jar', '.apk']
    
    suspicious_names = ['password', 'crack', 'keygen', 'patch', 'loader', 
                       'inject', 'stealer', 'rat', 'backdoor', 'trojan']
    
    for filename in archive_files:
        # Check extension
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        if f'.{ext}' in suspicious_extensions:
            detections.append(('archive_suspicious_file', 
                             f"Suspicious file in archive: {filename}"))
        
        # Check filename
        filename_lower = filename.lower()
        for name in suspicious_names:
            if name in filename_lower:
                detections.append(('archive_suspicious_name', 
                                 f"Suspicious filename: {filename}"))
                break
    
    return detections


def scan_pdf(filepath, rules):
    """
    Scan PDF files for embedded scripts and suspicious content
    """
    detections = []
    try:
        import PyPDF2
        
        with open(filepath, 'rb') as f:
            pdf = PyPDF2.PdfReader(f)
            
            # Check for JavaScript
            if '/JS' in str(pdf.metadata) or '/JavaScript' in str(pdf.metadata):
                detections.append(('pdf_javascript', 'PDF contains JavaScript'))
            
            # Extract text and scan
            text = ''
            for page in pdf.pages:
                text += page.extract_text()
            
            # Scan extracted text
            text_detections = scan_universal(text, rules, 'pdf')
            detections.extend(text_detections)
            
    except Exception as e:
        detections.append(('pdf_error', str(e)))
    
    return detections


def scan_image_metadata(filepath):
    """
    Scan image metadata for suspicious content
    """
    detections = []
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        
        img = Image.open(filepath)
        exif_data = img._getexif()
        
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                value_str = str(value)
                
                # Check for suspicious patterns in metadata
                suspicious = ['script', 'eval', 'exec', 'cmd', 'powershell', 
                            'http://', 'https://']
                
                for pattern in suspicious:
                    if pattern.lower() in value_str.lower():
                        detections.append(('image_metadata_suspicious', 
                                         f"{tag}: {value_str[:100]}"))
                        
    except Exception as e:
        pass
    
    return detections


def scan_config_file(content, rules):
    """
    Scan configuration files for credentials and suspicious settings
    """
    detections = []
    
    # Patterns specific to config files
    credential_patterns = [
        r'password\s*[:=]\s*["\']?[\w@#$%^&*]+',
        r'api[_-]?key\s*[:=]\s*["\']?[\w-]+',
        r'secret\s*[:=]\s*["\']?[\w-]+',
        r'token\s*[:=]\s*["\']?[\w-]+',
        r'auth\s*[:=]\s*["\']?[\w-]+',
    ]
    
    for pattern in credential_patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            detections.append(('config_credential', f"Found credential: {match.group()}"))
    
    # Also run universal scan
    universal_detections = scan_universal(content, rules, 'config')
    detections.extend(universal_detections)
    
    return detections

