from __future__ import print_function
from bcc import BPF
from sys import argv

import sys
import socket
import os
import time
import pyroute2 
import ctypes
import ipaddress



def main(bad_ips):
    TC_ARGS = dict(prio=100,handle=1)
    interface = "eth0"

    b = BPF(src_file='test.c')

    ban_ips = b.get_table('bad_ips')


    for bad_ip in bad_ips:
        addr = ctypes.c_uint32(int(bad_ip))
        ban_ips[addr] = ban_ips.Leaf(True)

    ipr = pyroute2.IPRoute()
    fn = b.load_func('tc', BPF.SCHED_CLS)
    links = ipr.link_lookup(ifname=interface)
    idx = links[0]


    try:
        ipr.tc('replace','clsact', idx)
        ipr.tc("add-filter", "bpf", idx,  fd=fn.fd, name=fn.name,
            parent="ffff:fff3",  action="drop", **TC_ARGS)
    except:
        print("filter already exists")

            

    print('filter added')

    try:
        b.trace_print()

    except KeyboardInterrupt:
        os.system("tc -s filter del dev eth0 egress")
        print('Filter Unloaded')
    # ipr.tc("del", "bpf", idx, parent="ffff:fff3")




if __name__== "__main__":
    main(bad_ips=[ipaddress.ip_address(ip) for ip in sys.argv[1:]])