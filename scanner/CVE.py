import requests


def search_cves(product, version):

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Create search term
    if version != "Unknown":
        search_term = product + " " + version
    else:
        search_term = product

    params = {
        "keywordSearch": search_term,
        "resultsPerPage": 5
    }

    print("\nSearching NVD for:", search_term)

    try:

        response = requests.get(
            url,
            params=params,
            timeout=15
        )

        if response.status_code != 200:

            print("NVD API Error:", response.status_code)

            return []

        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])

        results = []

        for item in vulnerabilities:

            cve = item.get("cve", {})

            cve_id = cve.get("id", "Unknown")

            # -----------------------------
            # Description
            # -----------------------------

            description = "No description available"

            for desc in cve.get("descriptions", []):

                if desc.get("lang") == "en":

                    description = desc.get("value")

                    break

            # -----------------------------
            # CVSS
            # -----------------------------

            cvss_score = "Not Available"
            severity = "Not Available"

            metrics = cve.get("metrics", {})

            # CVSS 4.0
            if metrics.get("cvssMetricV40"):

                cvss = metrics["cvssMetricV40"][0].get(
                    "cvssData", {}
                )

                cvss_score = cvss.get(
                    "baseScore",
                    "Not Available"
                )

                severity = cvss.get(
                    "baseSeverity",
                    "Not Available"
                )

            # CVSS 3.1
            elif metrics.get("cvssMetricV31"):

                cvss = metrics["cvssMetricV31"][0].get(
                    "cvssData", {}
                )

                cvss_score = cvss.get(
                    "baseScore",
                    "Not Available"
                )

                severity = cvss.get(
                    "baseSeverity",
                    "Not Available"
                )

            # CVSS 3.0
            elif metrics.get("cvssMetricV30"):

                cvss = metrics["cvssMetricV30"][0].get(
                    "cvssData", {}
                )

                cvss_score = cvss.get(
                    "baseScore",
                    "Not Available"
                )

                severity = cvss.get(
                    "baseSeverity",
                    "Not Available"
                )

            # CVSS 2.0
            elif metrics.get("cvssMetricV2"):

                cvss = metrics["cvssMetricV2"][0].get(
                    "cvssData", {}
                )

                cvss_score = cvss.get(
                    "baseScore",
                    "Not Available"
                )

                if cvss_score != "Not Available":

                    score = float(cvss_score)

                    if score >= 7.0:
                        severity = "HIGH"

                    elif score >= 4.0:
                        severity = "MEDIUM"

                    elif score > 0:
                        severity = "LOW"

                    else:
                        severity = "NONE"

            # -----------------------------
            # Save result
            # -----------------------------

            results.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity,
                "description": description
            })

        return results

    except requests.exceptions.RequestException as e:

        print("Connection Error:", e)

        return []

if __name__ == "__main__":

    results = search_cves("Varnish", "2.0.6")

    print("\n" + "-" * 70)
    print("Vulnerability Results")
    print("-" * 70)

    for cve in results:

        print("\nCVE:", cve["cve_id"])
        print("CVSS Score:", cve["cvss_score"])
        print("Severity:", cve["severity"])
        print("Description:", cve["description"])
