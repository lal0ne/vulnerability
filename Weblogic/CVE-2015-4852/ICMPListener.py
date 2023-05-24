import socket
import os
import struct
import ctypes

#
# Script taken from http://bt3gl.github.io/black-hat-python-building-a-udp-scanner.html
#
#

# host to listen on
# Currently set to listen on all interfaces.
# Change as required.
HOST = '0.0.0.0'

class ICMP(ctypes.Structure):
    _fields_ = [
    ('type',        ctypes.c_ubyte),
    ('code',        ctypes.c_ubyte),
    ('checksum',    ctypes.c_ushort),
    ('unused',      ctypes.c_ushort),
            ('next_hop_mtu',ctypes.c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

def main():
    # Check if the user running is the script is root.
    if not os.geteuid() == 0:
        sys.exit("[x] Sorry, you have to run this script with \'root\' privileges. Run with sudo or as root.")

    socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind(( HOST, 0 ))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while 1:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = raw_buffer[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

        # Create our IP structure
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        s_addr = socket.inet_ntoa(iph[8]);

        # Create our ICMP structure
        buf = raw_buffer[iph_length:iph_length + ctypes.sizeof(ICMP)]
        icmp_header = ICMP(buf)

        if icmp_header.type == 8:
            print("ICMP Request (Type:%d Code:%d) received from %s" %(icmp_header.type, icmp_header.code, str(s_addr)))

if __name__ == '__main__':
    main()
