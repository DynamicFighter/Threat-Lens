import socket
import sys
import threading
import subprocess
import xml.etree.ElementTree as ET

from CVE import search_cves
from Risk import assess_risk
from database import (
    create_database,
    save_scan,
    save_port,
    save_vulnerability
)


# --------------------------------------------------
# PROGRESS VARIABLES
# --------------------------------------------------

progress = {
    "status": "idle",
    "stage": "Waiting",
    "percentage": 0,
    "ports_scanned": 0,
    "total_ports": 0,
    "open_ports": 0,
    "total_cves": 0,
    "highest_cvss": 0,
    "overall_risk": "NOT ASSESSED",
    "message": ""
}

progress_lock = threading.Lock()


def update_progress(**kwargs):
    with progress_lock:
        progress.update(kwargs)


def get_progress():
    with progress_lock:
        return progress.copy()


# --------------------------------------------------
# MAIN SCANNER FUNCTION
# --------------------------------------------------

def run_scan(target_input, start_port, end_port):

    global progress

    create_database()

    # Reset progress
    update_progress(
        status="scanning",
        stage="Resolving Target",
        percentage=0,
        ports_scanned=0,
        total_ports=end_port - start_port + 1,
        open_ports=0,
        total_cves=0,
        highest_cvss=0,
        overall_risk="NOT ASSESSED",
        message="Resolving target..."
    )

    # --------------------------------------------------
    # TARGET RESOLUTION
    # --------------------------------------------------

    try:
        target = socket.gethostbyname(target_input)

    except socket.gaierror:

        update_progress(
            status="error",
            stage="Error",
            message="Name resolution error"
        )

        return None

    # --------------------------------------------------
    # PORT SCANNING
    # --------------------------------------------------

    open_ports = []

    total_ports = end_port - start_port + 1
    ports_scanned = 0

    update_progress(
        stage="Port Scanning",
        message="Scanning ports..."
    )

    def scan_port(port):

        nonlocal ports_scanned

        s = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        s.settimeout(2)

        result = s.connect_ex(
            (target, port)
        )

        if result == 0:

            open_ports.append(port)

            try:
                service = socket.getservbyport(port)
            except:
                service = "Unknown"

            print(
                "Port {} is OPEN - Service: {}".format(
                    port,
                    service
                )
            )

        s.close()

        with progress_lock:

            ports_scanned += 1

            percentage = int(
                (ports_scanned / total_ports) * 60
            )

            progress["ports_scanned"] = ports_scanned
            progress["open_ports"] = len(open_ports)
            progress["percentage"] = percentage

    # --------------------------------------------------
    # THREADS
    # --------------------------------------------------

    threads = []

    for port in range(
        start_port,
        end_port + 1
    ):

        thread = threading.Thread(
            target=scan_port,
            args=(port,)
        )

        thread.start()

        threads.append(thread)

    for thread in threads:
        thread.join()

    update_progress(
        percentage=60,
        open_ports=len(open_ports),
        stage="Port Scanning Complete",
        message="Port scanning completed."
    )

    # --------------------------------------------------
    # NMAP VERSION DETECTION
    # --------------------------------------------------

    if not open_ports:

        version_results = []

    else:

        update_progress(
            stage="Service Detection",
            percentage=65,
            message="Detecting services and versions..."
        )

        port_list = ",".join(
            map(str, sorted(open_ports))
        )

        nmap_path = "nmap"

        try:

            result = subprocess.run(
                [
                    nmap_path,
                    "-sV",
                    "--version-all",
                    "-p",
                    port_list,
                    target,
                    "-oX",
                    "-"
                ],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0:

                print("Nmap error:")
                print(result.stderr)

                version_results = []

            else:

                root = ET.fromstring(
                    result.stdout
                )

                version_results = []

                for port in root.findall(
                    ".//port"
                ):

                    port_number = port.get(
                        "portid"
                    )

                    state = port.find(
                        "state"
                    )

                    service = port.find(
                        "service"
                    )

                    if (
                        state is not None
                        and state.get("state") == "open"
                    ):

                        service_name = "Unknown"
                        product = "Unknown"
                        version = "Unknown"

                        if service is not None:

                            service_name = service.get(
                                "name",
                                "Unknown"
                            )

                            product = service.get(
                                "product",
                                "Unknown"
                            )

                            version = service.get(
                                "version",
                                "Unknown"
                            )

                        scan_result = {

                            "port": int(
                                port_number
                            ),

                            "service": service_name,

                            "product": product,

                            "version": version
                        }

                        version_results.append(
                            scan_result
                        )

                for item in version_results:

                    print(
                        "Port: {} | Service: {} | "
                        "Product: {} | Version: {}".format(
                            item["port"],
                            item["service"],
                            item["product"],
                            item["version"]
                        )
                    )
        except subprocess.TimeoutExpired:
            print("Nmap scan timed out.")
            version_results = []
        except FileNotFoundError:
            print(
                "Nmap executable was not found."
            )

            version_results = []

        except ET.ParseError:

            print(
                "Could not parse Nmap results."
            )

            version_results = []

    update_progress(
        percentage=75,
        stage="Service Detection Complete",
        message="Service detection completed."
    )

    # --------------------------------------------------
    # CVE / VULNERABILITY ASSESSMENT
    # --------------------------------------------------

    update_progress(
        stage="Vulnerability Assessment",
        percentage=80,
        message="Searching for vulnerabilities..."
    )

    all_cve_results = []

    assessment_possible = True

    for item in version_results:

        product = item["product"]
        version = item["version"]

        if product == "Unknown":

            assessment_possible = False

            continue

        if version == "Unknown":

            assessment_possible = False

            continue

        cve_results = search_cves(
            product,
            version
        )

        for cve in cve_results:

            cve["port"] = item["port"]

            all_cve_results.append(
                cve
            )

    # --------------------------------------------------
    # RISK ASSESSMENT
    # --------------------------------------------------

    update_progress(
        stage="Risk Assessment",
        percentage=90,
        message="Calculating security risk..."
    )

    risk_result = assess_risk(
        all_cve_results,
        assessment_possible
    )

    print("\n" + "=" * 70)
    print("FINAL RISK ASSESSMENT")
    print("=" * 70)

    print(
        "Total CVEs Found:",
        risk_result["total_cves"]
    )

    print(
        "Highest CVSS Score:",
        risk_result["highest_score"]
    )

    print(
        "Overall Risk:",
        risk_result["overall_risk"]
    )

    print("=" * 70)

    # --------------------------------------------------
    # SAVE TO DATABASE
    # --------------------------------------------------

    update_progress(
        stage="Saving Results",
        percentage=95,
        message="Saving scan results..."
    )

    display_target = target_input

    if target_input != target:
        display_target = "{} ({})".format(
            target_input,
            target
        )

    scan_id = save_scan(
        display_target,
        len(open_ports),
        risk_result["total_cves"],
        risk_result["highest_score"],
        risk_result["overall_risk"]
    )

    # Save ports
    
    saved_ports = set()

    # Save ports detected by Nmap
    for item in version_results:

        save_port(
            scan_id,
            item["port"],
            item["service"],
            item["product"],
            item["version"]
        )

        saved_ports.add(item["port"])

    # Save open ports not returned by Nmap
    for port in open_ports:

        if port not in saved_ports:

            try:
                service = socket.getservbyport(port)
            except:
                service = "Unknown"

            save_port(
                scan_id,
                port,
                service,
                "Unknown",
                "Unknown"
            )

    # Save vulnerabilities

    for cve in all_cve_results:

        save_vulnerability(
            scan_id,
            cve.get("port", 0),
            cve["cve_id"],
            cve["cvss_score"],
            cve["severity"],
            cve["description"]
        )

    # --------------------------------------------------
    # FINISHED
    # --------------------------------------------------

    update_progress(
        status="completed",
        stage="Scan Complete",
        percentage=100,
        ports_scanned=total_ports,
        open_ports=len(open_ports),
        total_cves=risk_result["total_cves"],
        highest_cvss=risk_result["highest_score"],
        overall_risk=risk_result["overall_risk"],
        message="Security scan completed."
    )

    print("\nScan results saved to database.")
    print("Scan ID:", scan_id)

    return {
        "scan_id": scan_id,
        "target": target,
        "open_ports": len(open_ports),
        "total_cves": risk_result["total_cves"],
        "highest_cvss": risk_result["highest_score"],
        "overall_risk": risk_result["overall_risk"]
    }


# --------------------------------------------------
# COMMAND LINE MODE
# --------------------------------------------------

if __name__ == "__main__":

    usage = (
        "python Nmap_CVE.py "
        "Target Start_Port End_Port"
    )

    if len(sys.argv) != 4:

        print(usage)
        sys.exit()

    target = sys.argv[1]

    start_port = int(
        sys.argv[2]
    )

    end_port = int(
        sys.argv[3]
    )

    print("-" * 70)
    print("Port Scanner")
    print("-" * 70)

    run_scan(
        target,
        start_port,
        end_port
    )
