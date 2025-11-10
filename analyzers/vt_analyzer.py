import vt
import hashlib
import os
from dotenv import load_dotenv
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
load_dotenv()

def get_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def scan_vt(filepath):
    detections = []
    API_KEY = os.getenv('VIRUS_TOTAL_API_KEY')
    if not API_KEY or len(API_KEY) == 0:
        detections.append(("virus_total", f"[ERROR] Invalid or missing API key"))
        return detections
    client = vt.Client(API_KEY)

    try:
        file_hash = get_sha256(filepath)
        report = client.get_object(f"/files/{file_hash}")
        for engine, result in report.last_analysis_results.items():
            if result["result"]:
                detections.append(("virus_total", f"({engine}) {result['result']} - {result['category']}"))
    except Exception as e:
        detections.append(("virus_total", f" [ERROR] {e}"))
    finally:
        client.close()

    return detections