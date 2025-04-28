# Project 2 - Faqirzada

import requests
import os
import json
import csv
import pandas as pd
from plotly.graph_objs import Bar, Scatter
from plotly import offline


def fetch_cve_data(year, month):
    """Fetch CVE data from NVD API, with caching."""
    api_key = "your_api_key_here"  # Replace with your actual API key
    start = f"{year}-{month:02d}-01T00:00:00.000Z"
    if month == 12:
        end = f"{year + 1}-01-01T00:00:00.000Z"
    else:
        end = f"{year}-{month + 1:02d}-01T00:00:00.000Z"

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": api_key}
    params = {"pubStartDate": start, "pubEndDate": end}
    cache_file = f"nvd_cache_{year}_{month:02d}.json"

    if os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as file:
            return json.load(file)
    else:
        resp = requests.get(url, headers=headers, params=params)
        if resp.status_code == 200:
            result = resp.json()
            with open(cache_file, "w", encoding="utf-8") as file:
                json.dump(result, file, indent=2)
            return result
        else:
            print(f"API request failed with status code: {resp.status_code}")
            return {}


def export_cve_to_csv(year, month):
    """Export CVE data into a structured CSV file."""
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
                    'cve_id': cve.get("id", ""),
                    'month': month,
                    'year': year,
                    'date_published': cve.get("published", ""),
                    'date_modified': cve.get("lastModified", ""),
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


def generate_charts(year, month, count=40):
    """Generate a bar chart and scatter plot for CVE data."""
    csv_file = f"cve_summary_{year}_{month:02d}.csv"
    data_frame = pd.read_csv(csv_file)

    # Only entries with a valid score
    data_frame = data_frame.dropna(subset=["score"])
    data_frame = data_frame[data_frame["score"] != ""]

    top_entries = data_frame.sort_values("score", ascending=False).head(count)

    # Bar Chart: Top CVEs by Base Score
    bar_chart = Bar(
        x=top_entries['cve_id'],
        y=top_entries['score'],
        text=top_entries['summary'],
        marker=dict(line=dict(width=1))
    )

    layout1 = dict(
        title='Top 40 CVEs by Base Score',
        xaxis=dict(title='CVE ID'),
        yaxis=dict(title='Base Score')
    )

    offline.plot(dict(data=[bar_chart], layout=layout1),
                 filename=f"severity_bar_{year}_{month:02d}.html",
                 auto_open=False)

    # Scatter Plot: Base Score vs Exploitability Score (Top 40)
    scatter_entries = top_entries.dropna(subset=["exploit_score"])
    scatter_chart = Scatter(
        x=scatter_entries['score'],
        y=scatter_entries['exploit_score'],
        text=scatter_entries['cve_id'],
        mode='markers'
    )

    layout2 = dict(
        title='Base Score vs Exploitability Score (Top 40 CVEs)',
        xaxis=dict(title='Base Score'),
        yaxis=dict(title='Exploitability Score')
    )

    offline.plot(dict(data=[scatter_chart], layout=layout2),
                 filename=f"exploit_scatter_{year}_{month:02d}.html",
                 auto_open=False)


if __name__ == "__main__":
    year_input = 2022
    month_input = 2
    export_cve_to_csv(year_input, month_input)
    generate_charts(year_input, month_input)
