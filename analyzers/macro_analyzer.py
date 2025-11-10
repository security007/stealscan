from oletools.olevba import VBA_Parser

def scan_macros(filepath, rules):
    detections = []
    try:
        vbaparser = VBA_Parser(filepath)
        if vbaparser.detect_vba_macros():
            keywords = rules.get("macro_keywords", [])
            for (_, _, _, code) in vbaparser.extract_macros():
                for k in keywords:
                    if k.lower() in code.lower():
                        short = code.strip().replace('\r', '').replace('\n', ' ')[:100]
                        detections.append(("macro_suspicious", f"{k} in macro: {short}"))
        vbaparser.close()
    except Exception as e:
        detections.append(("macro_error", str(e)))
    return detections
