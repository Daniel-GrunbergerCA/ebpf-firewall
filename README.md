# ebpf-firewall


This project is a simple application implementing an ebpf firewall. The firewall block requests based on: IP address, dns resolutions on specific hostnames. Besides that, we support giving a hostname only, and the application will resolve its IPs and block it.

The application work both in host and for docker containers using bridge network.

Examples:  
Run using local yaml file  
```python main.py  -i eth0  --use-from policies/egress.yaml```
<br/><br/>
Run using cli  
```python main.py -m egress -i eth0 --ips 216.58.212.206 --hostnames google.com```
<br/><br/>
```python main.py -m ingress -c alpine1 --ips 216.58.212.206```


Tested on linux kernel 5.16.0