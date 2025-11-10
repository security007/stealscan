import pefile

def scan_exe(filepath, rules):
    detections = []
    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories()

        api_rules = rules.get("suspicious_apis", [])
        api_bytes = [api.encode() for api in api_rules]

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name and imp.name in api_bytes:
                    detections.append(('suspicious_api', imp.name.decode()))
    except Exception as e:
        detections.append(('pe_error', str(e)))
    return detections
