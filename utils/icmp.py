import socket, psutil, ipaddress
from random import randbytes
from select import select
from typing import Dict
from .output import *
from impacket import ImpactPacket, ImpactDecoder


class ICMP:
    def __init__(self, dst: str, timeout) -> None:
        self.timeout = timeout
        self.srcs: Dict[str, socket.AddressFamily] = {}
        self.dst = dst
        self.alive_ips = set()
        netstat = psutil.net_if_stats()
        netaddr = psutil.net_if_addrs()
        for interface in netstat:
            if netstat[interface].isup:
                for i in netaddr[interface]:
                    if socket.AF_INET is i.family:
                        network = ipaddress.ip_network(i.address + '/' + i.netmask, False)
                        if ipaddress.ip_address(self.dst) in network:
                            self.srcs[i.address] = i.family

    def alive(self) -> bool:
        for src in self.srcs:
            ip = ImpactPacket.IP()
            ip.set_ip_src(src)
            ip.set_ip_dst(self.dst)
            icmp = ImpactPacket.ICMP()
            icmp.set_icmp_type(ImpactPacket.ICMP.ICMP_ECHO)
            icmp.contains(ImpactPacket.Data(randbytes(156)))
            ip.contains(icmp)
            s = socket.socket(self.srcs[src], socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            seq_id = 0
            ok =[]
            while 1:
                seq_id += 1
                icmp.set_icmp_id(seq_id)
                icmp.set_icmp_cksum(0)
                icmp.auto_checksum = 1
                if seq_id == 3:
                    if True in ok:
                        print("(ICMP) alive %s" % self.dst)
                        return True
                    else:
                        return False
                s.sendto(ip.get_packet(), (self.dst, 0))
                ready = select([s], [], [], self.timeout)[0]
                if ready:
                    reply = s.recvfrom(2000)[0]
                    rip = ImpactDecoder.IPDecoder().decode(reply)
                    ricmp = rip.child()
                    if rip.get_ip_dst() == src and rip.get_ip_src() == self.dst and ImpactPacket.ICMP.ICMP_ECHOREPLY == ricmp.get_icmp_type():
                        ok.append(True)
                else:
                    ok.append(False)

if __name__ == '__main__':
    for i in range(256):
        icmp = ICMP(f'192.168.100.{i}', 3)
        if icmp.alive():
            print('okok')