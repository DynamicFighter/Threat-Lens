import sqlite3
import os

DATABASE = os.path.join(
    os.path.dirname(
        os.path.abspath(__file__)
    ),
    "security_scanner.db"
)

def create_database():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_open_ports INTEGER,
            total_cves INTEGER,
            highest_cvss REAL,
            overall_risk TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            port INTEGER,
            service TEXT,
            product TEXT,
            version TEXT,
            FOREIGN KEY (scan_id)
                REFERENCES scans(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            port INTEGER,
            cve_id TEXT,
            cvss_score REAL,
            severity TEXT,
            description TEXT,
            FOREIGN KEY (scan_id)
                REFERENCES scans(id)
        )
    """)

    connection.commit()
    connection.close()


def save_scan(target, total_open_ports, total_cves,
              highest_cvss, overall_risk):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scans
        (target, total_open_ports, total_cves,
         highest_cvss, overall_risk)
        VALUES (?, ?, ?, ?, ?)
    """, (
        target,
        total_open_ports,
        total_cves,
        highest_cvss,
        overall_risk
    ))

    scan_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return scan_id


def save_port(scan_id, port, service, product, version):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO ports
        (scan_id, port, service, product, version)
        VALUES (?, ?, ?, ?, ?)
    """, (
        scan_id,
        port,
        service,
        product,
        version
    ))

    connection.commit()
    connection.close()


def save_vulnerability(scan_id, port, cve_id,
                       cvss_score, severity, description):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    if cvss_score == "Not Available":
        cvss_score = None

    cursor.execute("""
        INSERT INTO vulnerabilities
        (scan_id, port, cve_id, cvss_score,
         severity, description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        port,
        cve_id,
        cvss_score,
        severity,
        description
    ))

    connection.commit()
    connection.close()


if __name__ == "__main__":

    create_database()

    print("Database created successfully.")
