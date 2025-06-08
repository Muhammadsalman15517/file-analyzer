# file_scan.py

import requests
import hashlib
import time

API_KEY = '42f46a73f493c92d46ed0b6391dc0e5f5f5c009184a9e79299f582cffaa4b8af'  # ← apni API key daalna yahan

def scan_file(file_path):
    with open(file_path, "rb") as f:
        file_data = f.read()
    sha256_hash = hashlib.sha256(file_data).hexdigest()

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()["data"]["attributes"]["last_analysis_stats"]
        return sha256_hash, result

    # Upload and scan
    upload_url = "https://www.virustotal.com/api/v3/files"
    files = {"file": (file_path, open(file_path, "rb"))}
    response = requests.post(upload_url, headers=headers, files=files)

    if response.status_code != 200:
        return sha256_hash, {"error": "Upload failed"}

    analysis_id = response.json()["data"]["id"]

    # Wait for result
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        res = requests.get(analysis_url, headers=headers)
        data = res.json()
        status = data["data"]["attributes"]["status"]
        if status == "completed":
            result = data["data"]["attributes"]["stats"]
            return sha256_hash, result
        time.sleep(5)
