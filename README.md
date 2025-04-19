# Project-2-Faqirzada
import requests
import os
import json
import csv
import pandas as pd
from plotly.graph_objs import Bar, Scatter
from plotly import offline

 Function to fetch and cache CVE data from the NVD API
def fetch_cve_data(year, month):
    api_key = "your_api_key_here"  # Replace with your actual API key
    start = f"{year}-{month:02d}-01T00:00:00.000Z"
    end = f"{year + 1}-01-01T00:00:00.000Z" if month == 12 else f"{year}-{month + 1:02d}-01T00:00:00.000Z"
    endpoint = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start}&pubEndDate={end}"
    headers = {"apiKey": api_key}
    cache_file = f"nvd_cache_{year}_{month:02d}.json"

    if os.path.exists(cache_file):
        with open(cache_file, "r") as file:
            return json.load(file)
    else:
        resp = requests.get(endpoint, headers=headers)
        if resp.status_code == 200:
            result = resp.json()
            with open(cache_file, "w") as file:
                json.dump(result, file, indent=2)
            return result
        else:
            print(f"API request failed with status code: {resp.status_code}")
            return {}

 Function to write CVE data into a CSV file
def export_cve_to_csv(year, month):
    cve_data = fetch_cve_data(year, month)
    csv_file = f"cve_summary_{year}_{month:02d}.csv"

    headers = [
        'cve_id', 'month', 'year', 'date_published', 'date_modified',
        'exploit_score', 'impact_score', 'vector', 'attack_vector',
        'complexity', 'required_privileges', 'interaction_needed', 'scope',
        'conf_impact', 'integ_impact', 'avail_impact',
        'score', 'severity', 'summary'
    ]

    with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()

        for entry in cve_data.get("vulnerabilities", []):
            try:
                cve = entry.get("cve", {})
                metrics = cve.get("metrics", {})
                cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                writer.writerow({
                    'cve_id': cve.get("id"),
                    'month': month,
                    'year': year,
                    'date_published': cve.get("published"),
                    'date_modified': cve.get("lastModified"),
                    'exploit_score': metrics.get("cvssMetricV31", [{}])[0].get("exploitabilityScore", ""),
                    'impact_score': metrics.get("cvssMetricV31", [{}])[0].get("impactScore", ""),
                    'vector': cvss.get("vectorString", ""),
                    'attack_vector': cvss.get("attackVector", ""),
                    'complexity': cvss.get("attackComplexity", ""),
                    'required_privileges': cvss.get("privilegesRequired", ""),
                    'interaction_needed': cvss.get("userInteraction", ""),
                    'scope': cvss.get("scope", ""),
                    'conf_impact': cvss.get("confidentialityImpact", ""),
                    'integ_impact': cvss.get("integrityImpact", ""),
                    'avail_impact': cvss.get("availabilityImpact", ""),
                    'score': cvss.get("baseScore", ""),
                    'severity': cvss.get("baseSeverity", ""),
                    'summary': cve.get("descriptions", [{}])[0].get("value", "")
                })
            except Exception as err:
                print(f"Could not process entry: {err}")

 Function to visualize CVE data using Plotly
def generate_charts(year, month, count=40):
    csv_file = f"cve_summary_{year}_{month:02d}.csv"
    data_frame = pd.read_csv(csv_file)

    top_entries = data_frame.sort_values("score", ascending=False).head(count)
    bar_chart = Bar(
        x=top_entries['cve_id'],
        y=top_entries['score'],
        text=top_entries['summary']
    )
    layout1 = dict(title='Top CVEs by Base Score', xaxis=dict(title='CVE ID'), yaxis=dict(title='Score'))
    offline.plot(dict(data=[bar_chart], layout=layout1), filename=f"severity_bar_{year}_{month:02d}.html", auto_open=False)

    scatter_chart = Scatter(
        x=data_frame['score'],
        y=data_frame['exploit_score'],
        text=data_frame['cve_id'],
        mode='markers'
    )
    layout2 = dict(title='Base Score vs Exploitability', xaxis=dict(title='Base Score'), yaxis=dict(title='Exploitability'))
    offline.plot(dict(data=[scatter_chart], layout=layout2), filename=f"exploit_scatter_{year}_{month:02d}.html", auto_open=False)

 Entry point
if __name__ == "__main__":
    year_input = 2022
    month_input = 2
    export_cve_to_csv(year_input, month_input)
    generate_charts(year_input, month_input)
