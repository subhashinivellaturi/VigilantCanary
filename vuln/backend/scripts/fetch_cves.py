
import requests
import time
import pandas as pd
import os


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WEB_KEYWORDS = ["web", "website", "cross-site", "sql", "xss", "csrf", "cookie", "session", "http", "javascript", "php", "jsp", "html"]

# Read NVD API key from environment variable
NVD_API_KEY = os.getenv("NVD_API_KEY")



def fetch_web_cves(max_results=1000, out_csv="../data/web_cves_raw.csv"):
    results = []
    start_index = 0
    batch_size = 200
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    while len(results) < max_results:
        params = {
            "resultsPerPage": batch_size,
            "startIndex": start_index,
        }
        response = requests.get(NVD_API_URL, params=params, headers=headers)
        if response.status_code != 200:
            print(f"Error: {response.status_code}")
            break
        data = response.json()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            desc = cve.get("descriptions", [{}])[0].get("value", "")
            if any(keyword in desc.lower() for keyword in WEB_KEYWORDS):
                results.append({
                    "id": cve.get("id", ""),
                    "published": cve.get("published", ""),
                    "lastModified": cve.get("lastModified", ""),
                    "description": desc,
                    "severity": cve.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("baseSeverity", ""),
                    "cvssScore": cve.get("metrics", {}).get("cvssMetricV2", [{}])[0].get("baseScore", ""),
                })
        start_index += batch_size
        time.sleep(1)
        if not data.get("vulnerabilities", []):
            break
    df = pd.DataFrame(results)
    df.to_csv(out_csv, index=False)
    print(f"Saved {len(df)} web-related CVEs to {out_csv}")

if __name__ == "__main__":
    fetch_web_cves()
