import sys
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
import csv

# constantes del csv
filtrado = 'Filtrado'
cerrado = 'Cerrado'
abierto = 'Abierto'
abierto_filtrado = 'Abierto | Filtrado'
none = 'none'

def TCPScanner(ip, port):
    p = IP(dst=ip) / TCP(dport=port, flags='S')
    respTCP = sr1(p, verbose=False, timeout=1.0)

    if respTCP is None:
        return (filtrado, none)
    elif respTCP.haslayer(TCP):
        tcp_layer = respTCP.getlayer(TCP)
        if tcp_layer.flags == 0x12:
            sr1(IP(dst=ip) / TCP(dport=ports, flags='AR'), verbose = False, timeout = 1)
            return (abierto, str(tcp_layer.flags))
        elif tcp_layer.flags == 0x14:
            return (cerrado, str(tcp_layer.flags))

def UDPScanner(ip, port, ttl):
    pudp = sr1(IP(dst=ip)/UDP(dport=port),timeout=10)
    if (pudp is None):
        retrans = []
        for count in range(0, 3):
            retrans.append(sr1(IP(dst=ip) / UDP(dport=port), timeout=ttl))
        for item in retrans:
            if (item is not None):
                UDPScanner(ip, port, ttl)
        return abierto_filtrado
    elif(pudp.haslayer(UDP)):
        return abierto
    elif(pudp.haslayer(ICMP)):
        if (int(pudp.getlayer(ICMP).type) == 3 and int(pudp.getlayer(ICMP).code) == 3):
            return cerrado
        elif (int(pudp.getlayer(ICMP).type) == 3 and int(pudp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
            return filtrado
    else:
        return "CHECK"

max_port = int(sys.argv[2]) + 1 if len(sys.argv) > 2 else 1025
ip = sys.argv[1]

# csv
ports = range(1, max_port)
scannedfile = open('scanned-responses-' + ip + '.csv', 'a')
writer = csv.writer(scannedfile)
writer.writerow(['port','TCP','TCPflag','UDP'])

# scanning
for port in ports:
    (tcp, tcp_flags) = TCPScanner(ip, port)
    udp = UDPScanner(ip, port, 10)

    row_data = [str(port)]
    row_data.append(tcp)
    row_data.append(tcp_flags)
    row_data.append(udp)

    writer.writerow(row_data)

    print(row_data)

scannedfile.close()
