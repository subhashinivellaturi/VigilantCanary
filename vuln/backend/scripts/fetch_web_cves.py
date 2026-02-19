import requests
import pandas as pd
import time

# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Query parameters for web-related CVEs (e.g., 'web', 'website', 'cross-site', 'sql', 'xss', 'csrf', etc.)
WEB_KEYWORDS = ["web", "website", "cross-site", "sql", "xss", "csrf", "cookie", "session", "http", "javascript", "php", "jsp", "html"]

# Fetch CVEs from NVD API
def fetch_web_cves(max_results=1000):
    results = []
    start_index = 0
    batch_size = 200
    while len(results) < max_results:
        params = {
            "resultsPerPage": batch_size,
            "startIndex": start_index,
        }
        response = requests.get(NVD_API_URL, params=params)
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
        time.sleep(1)  # Avoid rate limits
        if not data.get("vulnerabilities", []):
            break
    return results

# Convert to DataFrame
web_cves = fetch_web_cves(max_results=1000)
df = pd.DataFrame(web_cves)

# Save to CSV
csv_path = "vuln/backend/data/web_cves_dataset.csv"
df.to_csv(csv_path, index=False)
print(f"Saved {len(df)} web-related CVEs to {csv_path}")

# Example: Load and train model (placeholder)
# from sklearn.ensemble import RandomForestClassifier
# ...
# model.fit(X, y)
