import requests
import pandas as pd
import os
import time
import random
from github import Github

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WEB_KEYWORDS = ["web", "website", "cross-site", "sql", "xss", "csrf", "cookie", "session", "http", "javascript", "php", "jsp", "html"]
NVD_API_KEY = os.getenv("NVD_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Fetch CVEs from NVD

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
                metrics = cve.get("metrics", {})
                cvss = metrics.get("cvssMetricV31", [{}])[0]
                results.append({
                    "id": cve.get("id", ""),
                    "published": cve.get("published", ""),
                    "lastModified": cve.get("lastModified", ""),
                    "description": desc,
                    "severity": cvss.get("baseSeverity", ""),
                    "cvssScore": cvss.get("baseScore", 0),
                    "cwe": cve.get("weaknesses", [{}])[0].get("description", [{}])[0].get("value", "")
                })
        start_index += batch_size
        time.sleep(1)
        if not data.get("vulnerabilities", []):
            break
    df = pd.DataFrame(results)
    df.to_csv(out_csv, index=False)
    print(f"Saved {len(df)} web-related CVEs to {out_csv}")

# Collect/generate normal samples from GitHub

def fetch_normal_samples_github(max_results=100, out_csv="../data/normal_samples.csv"):
    if not GITHUB_TOKEN:
        print("No GITHUB_TOKEN set. Skipping normal sample collection.")
        return
    g = Github(GITHUB_TOKEN)
    repos = g.search_repositories(query="language:python stars:>1000")
    samples = []
    for repo in repos[:max_results]:
        try:
            contents = repo.get_contents("")
            for content_file in contents:
                if content_file.path.endswith(('.py', '.js', '.php', '.html', '.jsp')):
                    code = content_file.decoded_content.decode(errors="ignore")
                    samples.append({"description": code[:500], "label": 0})
                    if len(samples) >= max_results:
                        break
            if len(samples) >= max_results:
                break
        except Exception:
            continue
    df = pd.DataFrame(samples)
    df.to_csv(out_csv, index=False)
    print(f"Saved {len(df)} normal samples to {out_csv}")

if __name__ == "__main__":
    fetch_web_cves()
    fetch_normal_samples_github()