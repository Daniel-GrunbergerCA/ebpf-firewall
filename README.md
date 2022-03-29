# ebpf-firewall


This project is a simple application implementing an ebpf firewall. The firewall block requests based on: IP address, dns resolutions on specific hostnames. It can be attached to both ingress and egress. Besides that, we support giving a hostname only, and the application will resolve its IPs and block it.

The application works both in host and for docker containers using bridge network.
Both whitelist and blacklist are supported.


## Examples:  
Run using local yaml file  
```python main.py  -i eth0  --use-from policies/egress.yaml```
<br/><br/>
Run using cli  
```python main.py -m egress -i eth0 --ips 216.58.212.206 --hostnames google.com```
<br/><br/>
```python main.py -m ingress -c alpine1 --ips 216.58.212.206```


Tested on linux kernel 5.16.0


For seeing results in UI, before running the main script run in a separate terminal:
``` cd flask && flask run ```  
Then browse to http://127.0.0.1:5000/



# Technichal overview

The python program uses the bcc framework to load the ebpf program and attach it to ingress/egress linux traffic control. The list of IPs and DNS hostnames are passed to the program using eBPF maps. The tracing events are submitted to userpace using eBPF events.

### Attaching to container
When attaching the filter to a container, all you need to provide is the container name (it needs to be up and running). The program maps the container to its veth. Ingress filter is applied as egress filter in the veth, and egress filter is applied as ingress filter. This is due to the fact that we do not run inside the container itself.
