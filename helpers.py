import socket
import struct
import requests
import json
import os

ADD_URL = "http://127.0.0.1:5000/add"

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def encode_dns(dns_name):
  if len(dns_name) + 1 > 255:
    raise Exception("DNS Name too long.")
  b_arr = bytearray()
  for element in dns_name.split('.'):
    sub_len = len(element)
    if sub_len > 63:
      raise ValueError('DNS label %s is too long' % element)
    b_arr.append(sub_len)
    b_arr.extend(element.encode('ascii'))
  b_arr.append(0)  
  return b_arr



def update_ui_data(event):
    protocol =  (event.protocol).decode("utf-8")
    status = (event.msg).decode("utf-8")
    src_ip = int2ip(event.src_ip)
    src_port = event.src_port
    dst_ip = int2ip(event.dst_ip)
    dst_port = event.dst_port
    payload={'src_ip': src_ip, 'src_port': src_port, 'dst_ip': dst_ip , 'dst_port': dst_port, 'protocol': protocol, 'status': status}
    try: 
        requests.post(url=ADD_URL, data=json.dumps(payload), headers={"Content-Type": "application/json"})
    
    except:
        pass



def resolve_hostname(hostname):
    return list(
        i        # raw socket structure
            [4]  # internet protocol info
            [0]  # address
        for i in 
        socket.getaddrinfo(
            hostname,
            0  # port, required
        )
        if i[0] is socket.AddressFamily.AF_INET  # ipv4

        # ignore duplicate addresses with other socket types
        and i[1] is socket.SocketKind.SOCK_RAW  
    )




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
                    if "@if" in line_veth and  line_veth.split("@if")[1] == device_id:
                        return line_veth.split('@if')[0]