import os
import magic
import zipfile
import rarfile

def identify_file_type(filepath):
    """Identify file type using both extension and magic bytes"""
    ext = os.path.splitext(filepath)[1].lower()
    
    # Try to get MIME type using magic
    try:
        mime = magic.from_file(filepath, mime=True)
    except:
        mime = None

    # Script files
    script_ext = ['.py', '.js', '.vbs', '.bat', '.ps1', '.sh', '.bash', '.cmd', 
                  '.php', '.pl', '.rb', '.lua', '.tcl', '.awk']
    
    # Office documents
    office_ext = ['.doc', '.docm', '.docx', '.xls', '.xlsm', '.xlsx', 
                  '.ppt', '.pptm', '.pptx', '.odt', '.ods', '.odp']
    
    # Executables and libraries
    exe_ext = ['.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.com', '.msi']
    
    # Archives
    archive_ext = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab', '.iso']
    
    # PDF files
    pdf_ext = ['.pdf']
    
    # Image files
    image_ext = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp']
    
    # Android/Java
    android_ext = ['.apk', '.dex', '.jar', '.class']
    
    # Configuration files
    config_ext = ['.ini', '.cfg', '.conf', '.config', '.xml', '.json', '.yaml', '.yml', '.toml']
    
    # Web files
    web_ext = ['.html', '.htm', '.css', '.asp', '.aspx', '.jsp']
    
    # Database files
    db_ext = ['.db', '.sqlite', '.sqlite3', '.mdb', '.accdb']
    
    # Determine type based on extension
    if ext in script_ext:
        return 'script'
    elif ext in office_ext:
        return 'office'
    elif ext in exe_ext:
        return 'exe'
    elif ext in archive_ext:
        return 'archive'
    elif ext in pdf_ext:
        return 'pdf'
    elif ext in image_ext:
        return 'image'
    elif ext in android_ext:
        return 'android'
    elif ext in config_ext:
        return 'config'
    elif ext in web_ext:
        return 'web'
    elif ext in db_ext:
        return 'database'
    
    # Use MIME type as fallback
    if mime:
        if 'text' in mime or 'script' in mime:
            return 'text'
        elif 'executable' in mime or 'application/x-dosexec' in mime:
            return 'exe'
        elif 'zip' in mime or 'compressed' in mime or 'archive' in mime:
            return 'archive'
        elif 'pdf' in mime:
            return 'pdf'
        elif 'image' in mime:
            return 'image'
        else:
            return 'other'
    
    return 'binary'


def load_file_content(filepath, max_size_mb=10):
    """Load file content with size limit"""
    try:
        file_size = os.path.getsize(filepath)
        if file_size > max_size_mb * 1024 * 1024:
            # For large files, read only first portion
            with open(filepath, 'rb') as f:
                content = f.read(max_size_mb * 1024 * 1024)
            return content
        
        # Try to read as text first
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except:
            # Fall back to binary
            with open(filepath, 'rb') as f:
                return f.read()
    except Exception as e:
        return None


def extract_strings_from_binary(filepath, min_length=4):
    """Extract readable strings from binary files"""
    strings = []
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
            
        current_string = b''
        for byte in content:
            # Check if byte is printable ASCII
            if 32 <= byte <= 126:
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    try:
                        strings.append(current_string.decode('ascii'))
                    except:
                        pass
                current_string = b''
        
        # Don't forget the last string
        if len(current_string) >= min_length:
            try:
                strings.append(current_string.decode('ascii'))
            except:
                pass
                
    except Exception as e:
        pass
    
    return '\n'.join(strings)


def is_archive(filepath):
    """Check if file is an archive"""
    ext = os.path.splitext(filepath)[1].lower()
    return ext in ['.zip', '.rar', '.7z', '.tar', '.gz']


def list_archive_contents(filepath):
    """List contents of archive files"""
    ext = os.path.splitext(filepath)[1].lower()
    contents = []
    
    try:
        if ext == '.zip':
            with zipfile.ZipFile(filepath, 'r') as zf:
                contents = zf.namelist()
        elif ext == '.rar':
            with rarfile.RarFile(filepath, 'r') as rf:
                contents = rf.namelist()
    except Exception as e:
        pass
    
    return contents