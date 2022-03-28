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
import requests
import helpers

DNS_TABLE = "dns_list"
EGRESS_TYPE = "egress"
INGRESS_TYPE = "ingress"
HOST_MODE = "HOST"
CONTAINER_MODE = "CONTAINER"
TABLE_NAME = "ips_list"
SOURCE_FILE = "ebpf.c"


class Firewall:
    def __init__(self, filter_type, ips,block, filter_mode, interface, container_name="", trace=False, dns_hostnames=""):
        self.filter_type = filter_type
        if self.filter_type == INGRESS_TYPE:
            self.func = "filter_src"
        else:
            self.func = "filter_dst"
        self.dns_hostnames = dns_hostnames
        self.ips = ips
        self.block = block
        self.filter_mode = filter_mode
        self.src_file = SOURCE_FILE
        self.container_name = container_name
        self.interface = interface
        self.trace = trace
        if self.filter_mode == CONTAINER_MODE and self.interface is None:
            self.interface = helpers.get_veth_for_container_name(container_name)
        self.ipr  = pyroute2.IPRoute()
        self.b =  BPF(src_file=self.src_file)

    
    def dns_filter(self):
        dns_table = self.b.get_table(DNS_TABLE)
        for hostname in self.dns_hostnames:
            self.add_cache_entry(dns_table, hostname)


    def add_cache_entry(self, dns_table, name):
        key = dns_table.Key()
        key_len = len(key.p)
        name_buffer = helpers.encode_dns(name)
        # Pad the buffer with null bytes if it is too short
        name_buffer.extend((0,) * (key_len - len(name_buffer)))
        key.p = (ctypes.c_ubyte * key_len).from_buffer(name_buffer)
        leaf = dns_table.Leaf()
        leaf.p = (ctypes.c_ubyte * 4).from_buffer(bytearray(4))
        dns_table[key] = leaf



    def apply_ingress(self, idx, fn, TC_ARGS):
        try:
            # add qdisc
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
            # use clsact qdisc, superset of ingress. Allow direct-action even for egress
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
        if self.dns_hostnames != "":
            self.dns_filter()
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
        print(f"{helpers.int2ip(event.src_ip)}:{event.src_port} -> {helpers.int2ip(event.dst_ip)}:{event.dst_port}. Protocol: {protocol}. Status: {msg}")
        helpers.update_ui_data(event)

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


