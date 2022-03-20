# filter for egress - host and container
from __future__ import print_function
from bcc import BPF
import socket
import os
import pyroute2 
import ctypes
import ipaddress
import json

EGRESS_TYPE = "egress"
INGRESS_TYPE = "ingress"
HOST_MODE = "HOST"
CONTAINER_MODE = "CONTAINER"
TABLE_NAME = "ips_list"


class Firewall:
    def __init__(self, func, interface, filter_type, ips,block, filter_mode, src_file, container_name=""):
        self.func = func
        self.filter_type = filter_type
        self.ips = ips
        self.block = block
        self.filter_mode = filter_mode
        self.src_file = src_file
        self.container_name = container_name
        if filter_mode == CONTAINER_MODE and self.interface == "":
            interface = self.get_veth_for_container_name()
        self.interface = interface

    
    def get_veth_for_container_name(self):
        inspect_data = os.popen(f'docker inspect {self.container_name}').read()
        json_obj = json.loads(inspect_data)[0]
        # get container pid
        pid = json_obj['State']['Pid']
        # get container interfaces info
        interfaces_info = os.popen(f"cat /proc/{pid}/net/igmp").read()
        """
        Example:
            Idx     Device    : Count Querier       Group    Users Timer    Reporter
            1       lo        :     1      V3
                                            010000E0     1 0:00000000               0
            4       eth0      :     1      V3
                                            010000E0     1 0:00000000               0
        """
        for line in interfaces_info.splitlines()[1::2]:
            device_id = line.split()[0]
            device = line.split()[1]
            if device == 'lo' or device_id == 'Idx':
                continue
            else:
                veths = os.popen('ip -br addr').read()
                # last digits of veth are veth id, which match the device_id
                for line_veth in veths.splitlines():
                    line_veth = line_veth.split()[0]
                    if line_veth[-1] == device_id:
                        return line_veth.split('@if')[0]



    def apply_egress_filter_for_host(self):
        TC_ARGS = dict(prio=100,handle=1)

        b = BPF(src_file=self.src_file)

        ips_table = b.get_table(TABLE_NAME)


        for bad_ip in self.ips:
            print(bad_ip)
            addr = ctypes.c_uint32(int(bad_ip))
            ips_table[addr] = ips_table.Leaf(True)

        ipr = pyroute2.IPRoute()
        fn = b.load_func(self.func, BPF.SCHED_CLS)
        links = ipr.link_lookup(ifname=self.interface)
        idx = links[0]
        if self.filter_type == EGRESS_TYPE:
            if self.filter_mode == HOST_MODE:
                try:
                    ipr.tc('replace','clsact', idx)
                    ipr.tc("add-filter", "bpf", idx,  fd=fn.fd, name=fn.name,
                        parent="ffff:fff3",  action="drop", **TC_ARGS)
                except:
                    print("filter already exists")

                print('filter applied')
                try:
                    b.trace_print()
                except KeyboardInterrupt:
                    # remove all filters
                    os.system(f"tc -s filter del dev {self.interface} egress")
                    print('Filter unloaded')
                    exit(0)

            else:
                try:
                    ipr.tc('add','ingress', idx, "ffff:")
                except:
                    print("filter already exists")

                ipr.tc("add-filter", "bpf", idx,  fd=fn.fd, name=fn.name, parent="ffff:",  action="drop", classid=2, **TC_ARGS)
            
                print('filter applied')

                try:
                    b.trace_print()

                except KeyboardInterrupt:
                    ipr.tc("del", "ingress", idx, "ffff:")
                    print('Filter unloaded')
                    exit(0)
        
        elif self.filter_type == INGRESS_TYPE:
            if self.filter_mode == HOST_MODE:
                try:
                    ipr.tc('add','ingress', idx, "ffff:")
                except:
                    print("filter already exists")

                ipr.tc("add-filter", "bpf", idx,  fd=fn.fd, name=fn.name, parent="ffff:",  action="drop", classid=2, **TC_ARGS)
            
                print('filter applied')

                try:
                    b.trace_print()

                except KeyboardInterrupt:
                    ipr.tc("del", "ingress", idx, "ffff:")
                    print('Filter unloaded')
                    exit(0)