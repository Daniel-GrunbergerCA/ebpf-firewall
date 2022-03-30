import optparse
import firewall
import ipaddress
import yaml
from yaml.loader import SafeLoader
import helpers


def init_parser():
    parser = optparse.OptionParser()
    parser.add_option("-m", "--mode", dest="mode", help="Filter mode. Options: ingress, egress")
    parser.add_option("-w", "--whitelist", dest="is_whitelist", help="Filter option  is whitelist", default=False,  action="store_true")
    parser.add_option("-c", "--container", dest="container", help="The container name")
    parser.add_option("-i", "--interface", dest="interface", help="The interface name")
    parser.add_option( "--ips", dest="ips", help="IPs list")
    parser.add_option( "--dns-hostnames", dest="dns_hostnames", help="DNS hostnames list", default="")
    parser.add_option( "--hostnames", dest="hostnames", help="hostnames list", default="")
    parser.add_option( "--block", dest="block", help="blacklist", default=True,  action="store_true")
    parser.add_option( "--use-from", dest="yaml_file", help="YAML config file ", default="")
    parser.add_option( "-t", "--trace", dest="trace", help="enable tracing", default=True,  action="store_true")
    return parser.parse_args()


def validate_args(options):
    if options.yaml_file != "":
        return
    if not options.mode:
        print("[E] No mode specified.  -h for help.")
        exit(0)
    elif not options.ips and not options.dns_hostnames:
        print("[E] No ips  nor dns hostnames specified.  -h for help.")
        exit(0)

def apply_egress(options, filter_mode):
    filter = firewall.Firewall( interface=options.interface, filter_type = firewall.EGRESS_TYPE, \
        ips=options.ips, block = options.block, filter_mode=filter_mode, is_whitelist=options.is_whitelist,\
            container_name = options.container, trace=options.trace, dns_hostnames=options.dns_hostnames)
    filter.apply_filter()


def apply_ingress(options, filter_mode):
    filter = firewall.Firewall( interface=options.interface, filter_type = firewall.INGRESS_TYPE, \
        ips=options.ips, block = options.block, filter_mode=filter_mode, is_whitelist=options.is_whitelist,\
            container_name = options.container, trace=options.trace, dns_hostnames=options.dns_hostnames)
    filter.apply_filter()

def parse_yaml(yaml_file):
    hostnames = ""
    dns_hostnames = ""
    ips = []
    with open(yaml_file) as f:
        data = yaml.load(f, Loader=SafeLoader)
        try:
            mode = data['mode']
            filter_type = data['filter-type']
        except KeyError:
            print('Invalid YAML.')
            exit(0)
        try:
            ips = data['ips']
        except KeyError:
            pass
        try:
            hostnames = data['hostnames']
        except KeyError:
            pass
        try:
            dns_hostnames = data['dns-hostnames']
        except KeyError:
            pass
    
    if len(ips) == 0 and len(hostnames) == 0 and len(dns_hostnames) == 0:
        print('Invalid YAML.')
        exit(0)
    return mode, ips, dns_hostnames, filter_type,  hostnames

def main():
    
    (options, arguments) = init_parser()
    
    validate_args(options)


    if options.yaml_file != "":
        options.block, options.ips, options.dns_hostnames, options.mode, options.hostnames = parse_yaml(options.yaml_file)
        for hostname in options.hostnames:
            ip_list = helpers.resolve_hostname(hostname)
        if options.hostnames != "":
            for ip in ip_list:
                options.ips.append(ip)
        options.ips=[ipaddress.ip_address(ip) for ip in  options.ips]

    else:
        options.ips=[ipaddress.ip_address(ip) for ip in  options.ips.split(",")]
        options.dns_hostnames = options.dns_hostnames.split(",")

    if options.mode == firewall.EGRESS_TYPE:
        if options.container:
            filter_mode = firewall.CONTAINER_MODE
        else:
            filter_mode = firewall.HOST_MODE

        apply_egress(options, filter_mode)



    elif options.mode == firewall.INGRESS_TYPE:
        if options.container:
            filter_mode=firewall.CONTAINER_MODE
        else:
            filter_mode=firewall.HOST_MODE

        apply_ingress(options, filter_mode)

  
if __name__ == "__main__":
    main()

# python main.py  -i eth0  --use-from policies/egress.yaml
# python main.py -m egress -i eth0 --ips 216.58.212.206 -t
# tc qdisc del dev vetha6b026c parent ffff:
#  docker run -dit --name alpine3 alpine ash
# docker start -a  alpine1  
# python main.py -m ingress -c alpine1 --ips 216.58.212.206
# tc qdisc del dev eth0 clsact