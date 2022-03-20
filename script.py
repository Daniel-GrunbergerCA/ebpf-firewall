
import sys
import socket
import os
import time
import pyroute2 
import ctypes
import ipaddress
import json


def get_veth_for_container_name(container_name):
    inspect_data = os.popen(f'docker inspect {container_name}').read()
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

print(get_veth_for_container_name('alpine3'))

