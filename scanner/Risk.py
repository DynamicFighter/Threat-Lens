def assess_risk(cve_results, assessment_possible=True):

    # No CVEs were found
    if not cve_results:

        if assessment_possible:
            overall_risk = "NO VULNERABILITIES FOUND"
        else:
            overall_risk = "NOT ASSESSED"

        return {
            "overall_risk": overall_risk,
            "highest_score": 0,
            "total_cves": 0
        }

    highest_score = 0
    highest_severity = "NONE"

    severity_order = {
        "NONE": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    for cve in cve_results:

        score = cve["cvss_score"]
        severity = cve["severity"].upper()

        if score != "Not Available":

            try:
                score = float(score)

                if score > highest_score:
                    highest_score = score

            except ValueError:
                pass

        if severity in severity_order:

            if severity_order[severity] > severity_order[highest_severity]:
                highest_severity = severity

    # Calculate overall risk
    if highest_score >= 9.0:
        overall_risk = "CRITICAL"

    elif highest_score >= 7.0:
        overall_risk = "HIGH"

    elif highest_score >= 4.0:
        overall_risk = "MEDIUM"

    elif highest_score > 0:
        overall_risk = "LOW"

    else:
        overall_risk = highest_severity

    return {
        "overall_risk": overall_risk,
        "highest_score": highest_score,
        "total_cves": len(cve_results)
    }


# ---------------------------------------
# TEST
# ---------------------------------------

if __name__ == "__main__":

    test_results = [
        {
            "cve_id": "CVE-2009-4488",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Test vulnerability"
        },
        {
            "cve_id": "CVE-TEST-0001",
            "cvss_score": 6.5,
            "severity": "MEDIUM",
            "description": "Test vulnerability"
        }
    ]

    result = assess_risk(test_results)

    print("\n" + "-" * 70)
    print("RISK ASSESSMENT")
    print("-" * 70)

    print("Total CVEs:", result["total_cves"])
    print("Highest CVSS Score:", result["highest_score"])
    print("Overall Risk:", result["overall_risk"])

    print("-" * 70)
