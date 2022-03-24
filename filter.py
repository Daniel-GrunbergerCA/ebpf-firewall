from __future__ import print_function
from bcc import BPF
import socket
import os
import pyroute2 
import ctypes
import ipaddress
import json
import ipaddress
import threading
import signal
import socket
import struct

EGRESS_TYPE = "egress"
INGRESS_TYPE = "ingress"
HOST_MODE = "HOST"
CONTAINER_MODE = "CONTAINER"
TABLE_NAME = "ips_list"


class Firewall:
    def __init__(self, func, filter_type, ips,block, filter_mode, src_file, interface, container_name="", trace=False):
        self.func = func
        self.filter_type = filter_type
        self.ips = ips
        self.block = block
        self.filter_mode = filter_mode
        self.src_file = src_file
        self.container_name = container_name
        self.interface = interface
        self.trace = trace
        if self.filter_mode == CONTAINER_MODE and self.interface is None:
            self.interface = self.get_veth_for_container_name()
        self.ipr  = pyroute2.IPRoute()
        self.b =  BPF(src_file=self.src_file)

    
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
                    if "@if" in line_veth and  line_veth.split("@if")[1] == device_id:
                        return line_veth.split('@if')[0]



    def apply_ingress(self, idx, fn, TC_ARGS):
        try:
            self.ipr.tc('add','ingress', idx, "ffff:")
        except:
            print("filter already exists")

        self.ipr.tc("add-filter", "bpf", idx,  fd=fn.fd, name=fn.name, parent="ffff:",  action="drop", classid=2, **TC_ARGS)
            
        print('ingress applied')

        if self.trace:
            self.handle_tracing()
        else:
            try:
                self.b.trace_print()
            except KeyboardInterrupt:
                self.unload_ingress(idx)

    def apply_egress(self, idx, fn, TC_ARGS):
        try:
            self.ipr.tc('replace','clsact', idx)
            self.ipr.tc("add-filter", "bpf", idx,  fd=fn.fd, name=fn.name,
                    parent="ffff:fff3",  action="drop", **TC_ARGS)
        except:
            print("filter already exists")

        print('filter applied')
        if self.trace:
            self.handle_tracing()
        else:
            try:
                self.b.trace_print()
            except KeyboardInterrupt:
                self.unload_egress()

    def apply_filter(self):
        TC_ARGS = dict(prio=100,handle=1)

        ips_table = self.b.get_table(TABLE_NAME)

        for bad_ip in self.ips:
            addr = ctypes.c_uint32(int(bad_ip))
            ips_table[addr] = ips_table.Leaf(True)

        
        fn = self.b.load_func(self.func, BPF.SCHED_CLS)
        links = self.ipr.link_lookup(ifname=self.interface)
        idx = links[0]
        if self.filter_type == EGRESS_TYPE:
            if self.filter_mode == HOST_MODE:
                self.apply_egress(idx,fn, TC_ARGS)

            else:
                # apply ingress for container egress
                self.filter_type = INGRESS_TYPE
                self.apply_ingress(idx,fn, TC_ARGS)

        elif self.filter_type == INGRESS_TYPE:
            if self.filter_mode == HOST_MODE:
                self.apply_ingress(idx,fn, TC_ARGS)
            else:
                self.filter_type = EGRESS_TYPE
                self.apply_egress(idx,fn, TC_ARGS)


    def handle_tracing(self):
        self.b["events"].open_perf_buffer(self.print_event)
        global t1
        t1 = threading.Thread(target=self.task1)
        t1.daemon = True
        t1.start()


        signal.signal(signal.SIGINT, self.signal_handler)
        forever = threading.Event()
        forever.wait()

    def task1(self):
        while 1:
            self.b.perf_buffer_poll()


    def print_event(self, cpu, data, size):
        event = self.b["events"].event(data)
        protocol =  (event.protocol).decode("utf-8")
        msg = (event.msg).decode("utf-8")
        print(f"{int2ip(event.src_ip)}:{event.src_port} -> {int2ip(event.dst_ip)}:{event.dst_port}. Protocol: {protocol}. Status: {msg}")


    def signal_handler(self, signal, frame):
        if self.filter_type == EGRESS_TYPE:
            self.unload_egress()
        else:
            links = self.ipr.link_lookup(ifname=self.interface)
            idx = links[0]
            self.unload_ingress(idx)

    def unload_egress(self):
        os.system(f"tc -s filter del dev {self.interface} egress")
        print('Filter unloaded')
        exit(0)

    def unload_ingress(self, idx):
        self.ipr.tc("del", "ingress", idx, "ffff:")
        print('Filter unloaded')
        exit(0)

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


