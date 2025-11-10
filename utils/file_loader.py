import os

def identify_file_type(filepath):
    ext = os.path.splitext(filepath)[1].lower()

    script_ext = ['.py', '.js', '.vbs', '.bat', '.ps1']
    office_ext = ['.doc', '.docm', '.docx', '.xls', '.xlsm']
    exe_ext = ['.exe', '.dll']

    if ext in script_ext:
        return 'script'
    elif ext in office_ext:
        return 'office'
    elif ext in exe_ext:
        return 'exe'
    else:
        return 'unknown'

def load_file_content(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return ''
