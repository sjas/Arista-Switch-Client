import re, json
from collections import OrderedDict

def parse_show_interfaces_json(output):
    raw_interface_info = json.loads(output)
    raw_interface_info = raw_interface_info["interfaces"]
    raw_interface_info = OrderedDict(sorted(raw_interface_info.items()))
    list_of_interface_info = []
    for iface, details in raw_interface_info.items():
        interface_details = {}
        interface_details["hardware_type"] = details["hardware"]
        interface_details["description"] = details["description"]
        interface_details["link_status"] = details["interfaceStatus"]
        interface_details["protocol_status"] = details["lineProtocolStatus"]
        interface_details["bia"] = details["burnedInAddress"] if "burnedInAddress" in details.keys() else ""
        interface_details["bandwidth"] = details["bandwidth"] 
        interface_details["address"] = details["physicalAddress"] if "physicalAddress" in details.keys() else ""
        interface_details["interface"] = details["name"]
        interface_details["mtu"] = details["mtu"]
        interface_details["ip_address"] = details["interfaceAddress"]
        list_of_interface_info.append(interface_details)
    return list_of_interface_info

def sortInterfaceConfig(interfaceSection):
    #Create dictionary where interface names are keys
    interfaces = [iface.strip() for iface in interfaceSection.split("!")]
    interface_dict = {}
    for interface in interfaces:
        iface_name = re.match(r'interface (([a-zA-Z,-]+)([\d,\/]+))', interface)
        if iface_name:
            interface_dict[iface_name.group(1)] = interface
        
    sorted_keys = sorted(interface_dict.keys(), cmp=interfaceComparator)
       
    config = []
    for key in sorted_keys:
        config.append(interface_dict[key])

    return "\n!\n".join(config) + "\n!\n"

def interfaceComparator(a, b):
    match_a = re.match('\D+', a)
    match_b = re.match('\D+', b)
    if match_a and match_b:
        if match_a.group(0).lower() < match_b.group(0).lower(): return -1
        if match_a.group(0).lower() > match_b.group(0).lower(): return 1
        else:
            if len(match_a.group(0)) < len(a) or len(match_b.group(0)) < len(b):
                return interfaceComparator(a[match_a.end(0):], b[match_b.end(0):])
    match_a = re.match('\d+', a)
    match_b = re.match('\d+', b)
    if match_a and match_b:
        if int(match_a.group(0)) < int(match_b.group(0)): return -1
        if int(match_a.group(0)) > int(match_b.group(0)): return 1
        else:
            if len(match_a.group(0)) < len(a) or len(match_b.group(0)) < len(b):
                return interfaceComparator(a[match_a.end(0):], b[match_b.end(0):])
    return 0