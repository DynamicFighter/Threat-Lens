import socket
import sys
import time 
import threading
import concurrent.futures
import subprocess

usage = "python3 port_scanner.py Target Start_Port End_Port"

#cd "D:\Abdullah\TY Project\Port Scanner"
#dir
#python Servicedect.py 192.168.1.1 1 100

print("-" *70)
print ("Port Scanner")
print("-" *70)

if(len(sys.argv)!=4):
    print(usage)
    sys.exit()

try:
    target = socket.gethostbyname(sys.argv[1])
except socket.gaierror:
    print("Name resolution error")
    sys.exit()

start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

def scan_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)

    result = s.connect_ex((target, port))

    if result == 0:
        try:
            service = socket.getservbyport(port)
        except:
            service = "Unknown"

        print("Port {} is OPEN - Service: {}".format(port, service))

    s.close()

# This Function Is Only For PortScaning
#def scan_port(port):
 #   s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 #   s.settimeout(2)
 #   result = s.connect_ex((target, port))
 #   if(not result):
 #      print("Port {} is OPEN".format(port))
 #  s.close()

# For Normal Port Scanner Without Thread
#for port in range(start_port, end_port+1):
 #   thread = threading.Thread(target=scan_port,args =(port,))
 #   thread.start()

threads = []

for port in range(start_port, end_port + 1):
    thread = threading.Thread(target=scan_port, args=(port,))
    thread.start()
    threads.append(thread)

for thread in threads:
   thread.join()

#with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
   # executor.map(scan_port, range(start_port, end_port + 1))
