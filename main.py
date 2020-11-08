import sys
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP

def UDPScanner(ip,port,ttl):
    pudp = sr1(IP(dst=ip)/UDP(dport=i),timeout=10)
    if (str(type(pudp )) ==" < type 'NoneType' > "):
        retrans = []
        for count in range(0, 3):
            retrans.append(sr1(IP(dst=ip) / UDP(dport=port), timeou=ttl))
        for item in retrans:
            if (str(type(item)) !=" < type ‘NoneType’ > "):
                UDPScanner(ip, port, ttl)
                return "Abierto | Filtrado"
            elif(pudp.haslayer(UDP)):
                return "Abierto"
            elif (pudp.haslayer(ICMP)):
                if (int(pudp.getlayer(ICMP).type) == 3 and int(pudp.getlayer(ICMP).code) == 3):
                    return "Cerrado"
                elif (int(pudp.getlayer(ICMP).type) == 3 and int(pudp.getlayer(ICMP).code) in [1, 2, 9, 10,13]):
                    return "Filtrado"
            else:
                return "CHECK"

ports = [port for port in range(1, 1025)]

ip = sys.argv[1]
for i in ports:
    p = IP(dst=ip)/TCP(dport=i, flags='S')
    print(i ,end='')
    respTCP = sr1(p, verbose=False, timeout=1.0)
    if respTCP is None:
        print(" filtrado")
    elif respTCP.haslayer(TCP):
        tcp_layer = respTCP.getlayer(TCP)
        if tcp_layer.flags == 0x12:
            print(" abierto", tcp_layer.flags)
            sr1(IP(dst=ip) / TCP(dport=ports, flags='AR'), verbose = False, timeout = 1)
        elif 0x14 == tcp_layer.flags:
            print(" cerrado", tcp_layer.flags)
    UDPScanner(ip,i,10)
