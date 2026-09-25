import sqlite3

DATABASE = "security_scanner.db"

connection = sqlite3.connect(DATABASE)
cursor = connection.cursor()

print("\n" + "=" * 70)
print("SAVED SCANS")
print("=" * 70)

cursor.execute("SELECT * FROM scans")

scans = cursor.fetchall()

for scan in scans:
    print(scan)


print("\n" + "=" * 70)
print("SAVED PORTS")
print("=" * 70)

cursor.execute("SELECT * FROM ports")

ports = cursor.fetchall()

for port in ports:
    print(port)


print("\n" + "=" * 70)
print("SAVED VULNERABILITIES")
print("=" * 70)

cursor.execute("SELECT * FROM vulnerabilities")

vulnerabilities = cursor.fetchall()

for vulnerability in vulnerabilities:
    print(vulnerability)


connection.close()
