from ntc_templates.parse import parse_output
from models import switchModelInfo
from chips import chipModelInfo
import json
from collections import OrderedDict
import ipaddress
import switch_helpers
 
class Switch():
    """
    Class to act as an EOS Switch object.  Uses Netmiko (SSH) or jsonrpclib (EAPI) to execute switch functions. 
    """
    def __init__(self, ip_address=None, username=None, password=None):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.hostname = None
        self.fqdn = None
        self.serial_number = None
        self.mac_address = None
        self.eos_version = None
        self.model = None
        self.chipset = None
        self.interfaces = None

    def __str__(self):
        output = ""
        output += "Switch: {}\n".format(self.hostname)
        output += "  {:15} {}\n".format("FQDN:", self.fqdn)
        output += "  {:15} {}\n".format("IP address:", self.ip_address)
        output += "  {:15} {}\n".format("MAC address:", self.mac_address)
        output += "  {:15} {}\n".format("EOS version:", self.eos_version)
        output += "  {:15} {}\n".format("Serial Number:", self.serial_number)
        output += "  {:15} {}\n".format("Model:", self.model)
        output += "  {:15} {}\n".format("Chipset:", self.chipset)
        return output

    def send_commands(self, commands, enable=True, method="eapi"):
        """
        Executes commands on an Arista switch

            cmds ( [str] ):  A list of commands to be executed on the switch

            method ( str ): A value that determines what method to send a command
                            Options are:
                                eapi
                                netmiko

            Returns a list of dictionaries with a single key/value pair of command/output

        """
        if method == "ssh":
            return self.send_commands_via_netmiko(commands, enable=enable)
        else:
            return self.send_commands_via_eapi(commands, enable=enable)

    def send_commands_via_eapi(self, commands, enable=True):
        """
        Uses the Server class from jsonrpclib to make API calls to the Arista EAPI running on switches

            cmds ( [str] ):  A list of commands to be executed on the switch

            Returns a list of dictionaries with a single key/value pair of command/output

        """
        from jsonrpclib import Server
        import ssl
        try:
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            pass
        else:
            ssl._create_default_https_context = _create_unverified_https_context


        if type(commands) == str:
            commands = [commands]

        if self.ip_address is not None:
            url = "https://{}:{}@{}/command-api".format(self.username, self.password, self.ip_address)


        try:
            switch = Server(url)
            if enable==True:
                commands.insert(0, "enable")
            response = switch.runCmds(1, commands, "text")
        except Exception as e:
            print(e)
            return None
        else:
            if enable==True:
                response.pop(0)
            for index, output in enumerate(response):
                for k, v in output.items():
                    output[commands[index + 1]] = output.pop(k)
            return response

    def send_commands_via_netmiko(self, commands, enable=True):

        """
        Uses the Netmiko library to ssh to the Arista switches and sends commands

            cmds ( [str] ):  A list of commands to be executed on the switch

            Returns a list of dictionaries with a single key/value pair of command/output

        """
        from netmiko import ConnectHandler, NetmikoAuthError, NetmikoTimeoutError

        response = []
        try:
            connection = ConnectHandler(device_type="arista_eos", ip=self.ip_address, username=self.username, 
                                        password=self.password, secret=self.password)
        except (NetmikoAuthError, NetmikoTimeoutError, ValueError) as e:
            print(e)
            return None
        else:
            if type(commands) == str:
                commands = [commands]

            if enable == True:
                connection.enable()

            for command in commands:
                output = {command: connection.send_command_timing(command)}
                response.append(output)
            connection.disconnect()
        return response

    def get_facts(self):
        hostname_output = self.send_commands("show hostname | json")[0]["show hostname | json"]
        version_output = self.send_commands("show version | json")[0]["show version | json"]
        interface_output = self.send_commands("show interfaces")[0]["show interfaces"]
        interface_parsed = parse_output(platform="arista_eos", command="show interfaces", data=interface_output)
        self.hostname = json.loads(hostname_output)["hostname"]
        self.fqdn = json.loads(hostname_output)["fqdn"]
        self.mac_address = json.loads(version_output)["systemMacAddress"]
        self.serial_number = json.loads(version_output)["serialNumber"]
        self.eos_version = json.loads(version_output)["version"]
        self.model = json.loads(version_output)["modelName"]
        self.chipset = switchModelInfo["-".join(json.loads(version_output)["modelName"].split("-")[:3])]["chipset"]
        self.interfaces = interface_parsed


    #svi_address range has to be unicode for python 2
    def build_mlag(self, role, mlag_domain_id="MLAG_DOMAIN", mlag_svi_address_range=unicode("10.179.248.0/31"), number_of_interfaces=2, interfaces=None,
                    port_channel=2000, vlan=4094, trunk_group_name="MLAG_Peer", ibgp=False, ibgp_address_range=unicode("10.179.253.0/31"), ibgp_vrfs_to_vlans={"default":1}, asn=None, 
                    virtual_mac="00:1c:73:00:00:34", reload_delay=(300, 360)):
        """
        Returns a potential mlag configuration based on input arguments.

        Args:
            mlag_domain_id (str) --> name of mlag domain-id
            role ( str ) -> "primary" or "secondary"  Does NOT literally define primary or secondary role
            svi_address_range ( str ) -> format: "a.b.c.d/xy" - address for SVI which will be peer link IP address 
            port_channel ( int ) -> port channel interface number for MLAG peer link
            vlan ( int ) -> vlan id for MLAG traffic
            trunk_group_name ( str )
            ibgp ( bool ) -> flag to determine if ibgp is needed (for L3LS)
            ibgp_address_range -> format: "a.b.c.d/xy" - address for iBGP stuff (ask George)
        """
        mlag_config = ""
        mlag_general_section = ""
        mlag_vlan_section = ""
        mlag_interface_section = ""
        mlag_mlag_section = ""
        mlag_vrf_section = ""
        mlag_ibgp_section = ""

        mlag_mlag_section += "ip virtual-router mac-address {}\n".format(virtual_mac)
        mlag_mlag_section += "!\n"


        hosts = list(ipaddress.ip_network(mlag_svi_address_range).hosts())
        if len(hosts) < 2:
            assert "{}  is an invalid address range for SVI".format(mlag_svi_address_range)
        if role == "primary":
            svi_address = hosts[0]
            peer_address = hosts[1]
        else:
            svi_address = hosts[1]
            peer_address = hosts[0]
        #Get interfaces
        if interfaces is not None:
            #check to make sure number of interfaces = len of interfaces
            if number_of_interfaces != len(number_of_interfaces):
                #error
                assert "Error: number of interfaces does not match amount of interfaces given"
                return
            #check to see if interfaces given are in self.interfaces
            for interface in interfaces:
                for iface in self.interfaces:
                    if iface["interface"] == interface:
                        break
                assert "{} cannot be found on switch".format(interface)
                return
        else:
            #Get last x most common port speed interfaces of switch
            interfaces = next(iter(self.order_interfaces_by_most_common_speed().values()))[-(number_of_interfaces):]

        #Configure MLAG vlan
        mlag_vlan_section += "vlan {}\n".format(vlan)
        mlag_vlan_section += "  name MLAG-Peer-Vlan\n"
        mlag_vlan_section += "  trunk group {}\n".format(trunk_group_name)
        mlag_vlan_section += "!\n"

        #Disable spanning tree on MLAG vlan
        mlag_general_section += "no spanning-tree vlan {}\n".format(vlan)
        mlag_general_section += "!\n"

        #Configure physical interface configs
        for interface in interfaces:
            mlag_interface_section += "interface {}\n".format(interface)
            mlag_interface_section += "  description MLAG Interface\n"
            mlag_interface_section += "  switchport mode trunk\n"
            mlag_interface_section += "  channel-group {} mode active\n".format(port_channel)
            mlag_interface_section += "!\n"

        #Configure port channel
        mlag_interface_section += "interface Port-Channel{}\n".format(port_channel)
        mlag_interface_section += "  description MLAG Peer Port-Channel\n"
        mlag_interface_section += "  load-interval {}\n".format(5)
        mlag_interface_section += "  switchport mode trunk\n"
        mlag_interface_section += "  switchport trunk group {}\n".format(trunk_group_name)
        mlag_interface_section += "!\n"

        #Configure SVI
        mlag_interface_section += "interface Vlan{}\n".format(vlan)
        mlag_interface_section += "  description MLAG peer link\n"
        mlag_interface_section += "  mtu {}\n".format(9214)
        mlag_interface_section += "  no autostate\n"
        mlag_interface_section += "  ip address {}/{}\n".format(svi_address, ipaddress.ip_network(mlag_svi_address_range).prefixlen)
        mlag_interface_section += "!\n"

        #Configure mlag
        mlag_mlag_section += "mlag\n"
        mlag_mlag_section += "  domain-id {}\n".format(mlag_domain_id)
        mlag_mlag_section += "  local-interface vlan {}\n".format(vlan)
        mlag_mlag_section += "  peer-address {}\n".format(peer_address)
        mlag_mlag_section += "  peer-link port-channel {}\n".format(port_channel)
        mlag_mlag_section += "  reload-delay mlag {}\n".format(reload_delay[0])
        mlag_mlag_section += "  reload-delay non-mlag {}\n".format(reload_delay[1])
        mlag_mlag_section += "!\n"

        if ibgp == True:
            hosts = list(ipaddress.ip_network(ibgp_address_range).hosts())
            if role == "primary":
                ibgp_svi_address = hosts[0]
                ibgp_neighbor_address = hosts[1]
            else:
                ibgp_svi_address = hosts[1]
                ibgp_neighbor_address = hosts[0]

            for vrf, vlan in ibgp_vrfs_to_vlans.items():
                if vrf == "default":
                    interface = next(iter(self.order_interfaces_by_most_common_speed().values()))[-(number_of_interfaces+1):-(number_of_interfaces)]
                    if len(interface) == 0:
                        assert "Could not retrieve an interface"
                        break
                    mlag_interface_section += "interface {}\n".format(interface[0])
                    mlag_interface_section += "  no switchport\n"
                    mlag_interface_section += "  ip address {}/{}\n".format(ibgp_svi_address,ipaddress.ip_network(ibgp_address_range).prefixlen)
                    mlag_interface_section += "!\n"
                else:
                    mlag_vrf_section += "vrf instance {}\n".format(vrf)
                    mlag_vrf_section += "!\n"
                    mlag_vlan_section += "vlan {}\n".format(vlan)
                    mlag_vlan_section += "  name {}_IBGP_PEER\n".format(vrf)
                    mlag_vlan_section += "  trunk group {}_IBGP_PEER\n".format(vrf)
                    mlag_vlan_section += "!\n"
                    mlag_interface_section += "interface Vlan{}\n".format(vlan)
                    mlag_interface_section += "  description {}_IBGP_PEER\n".format(vrf)
                    mlag_interface_section += "  vrf forwarding {}\n".format(vrf)
                    mlag_interface_section += "  ip addrress {}/{}\n".format(ibgp_svi_address,ipaddress.ip_network(ibgp_address_range).prefixlen)
                    mlag_interface_section += "!\n"

            mlag_ibgp_section += "router bgp {}\n".format(asn)
            mlag_ibgp_section += "  neighbor {} remote-as {}\n".format(ibgp_neighbor_address, asn)
            mlag_ibgp_section += "  neighbor {} next-hop self\n".format(ibgp_neighbor_address)
            mlag_ibgp_section += "  neighbor {} allowas-in 1\n".format(ibgp_neighbor_address)
            mlag_ibgp_section += "  neighbor {} maximum-routes 12000\n".format(ibgp_neighbor_address)
            mlag_ibgp_section += "!\n"

        mlag_interface_section = switch_helpers.sortInterfaceConfig(mlag_interface_section)

        mlag_elements = [mlag_general_section, mlag_vlan_section, mlag_vrf_section, mlag_interface_section,
                        mlag_mlag_section, mlag_ibgp_section]

        return "".join(mlag_elements)

    def build_ip_interface_underlay(self, interfaces_to_ips=None):
        """
        Args:
            interfaces_to_ips ({str: str}) ->  key is the interface, value is the ip address
            mlag_enabled ( bool ) -> Used to determine if mlag is enabled
            virtual_mac ( str ) -> virtual mac used for mlag switches to receive traffic
        """
        if interfaces_to_ips is None:
            assert "Need interface to ip dictionary"
            return

        #build config
        ip_interface_config = []

        #Sort interfaces
        interfaces_to_ips = OrderedDict(sorted(interfaces_to_ips.items()))

        for interface, ip_address in interfaces_to_ips.items():
            ip_interface_config.append("interface {}".format(interface))
            ip_interface_config.append("  no switchport")
            ip_interface_config.append("  ip address {}".format(ip_address))
            ip_interface_config.append("!")   

        ip_interface_config = switch_helpers.sortInterfaceConfig("\n".join(ip_interface_config))
        return ip_interface_config

    def build_bgp_underlay(self, asn, role, underlay_source_address, remote_ases_and_neighbors, underlay_source_interface="Loopback0"):
        """
        Args
            asn ( int ) --> asn number
            role ( str ) --> "leaf" or "spine"
            underlay_source_address (str)  --> address of loopback 0 in CIDR notation; i.e. "1.1.1.1/32"
            number of neighbors ( int ) -->  number of neighbors to peer with
            mlag_enabled ( bool ) --> flag to signal if mlag is enabled (should we set a virtual-router mac-address)
            remote_ases_and_neighbors ( {int: [str]} ) --> dictionary where keys are keys are remote ases and values are neighbors that will belong to those ases.
                                                            Example: {65000:["172.16.200.1","172.16.200.3"]}
        """
        #Calculate number of neighbors
        number_of_neighbors = 0
        for bgp_asn, neighbors in remote_ases_and_neighbors.items():
            number_of_neighbors += len(neighbors)

        bgp_underlay_config = []

        bgp_underlay_config.append("interface {}".format(underlay_source_interface))
        bgp_underlay_config.append("  ip address {}".format(underlay_source_address))
        bgp_underlay_config.append("!")

        bgp_underlay_config.append("ip routing")
        bgp_underlay_config.append("!")
        bgp_underlay_config.append("service routing protocols model multi-agent")
        bgp_underlay_config.append("!")

        #Build bgp config
        if role == "leaf":
            peer_group = "SPINE"
        elif role == "spine":
            peer_group = "LEAF"
        else:
            assert "Invalid role"
            return
        bgp_underlay_config.append("router bgp {}".format(asn))
        bgp_underlay_config.append("  router-id {}".format(underlay_source_address.split("/")[0]))
        bgp_underlay_config.append("  maximum-paths {} ecmp {}".format(number_of_neighbors, number_of_neighbors))
        bgp_underlay_config.append("  neighbor {} peer-group".format(peer_group))
        bgp_underlay_config.append("  neighbor {} fall-over bfd".format(peer_group))
        bgp_underlay_config.append("  neighbor {} send-community".format(peer_group))
        bgp_underlay_config.append("  neighbor {} maximum-routes 12000".format(peer_group))
        for remote_as, bgp_neighbors in remote_ases_and_neighbors.items():
            for neighbor in bgp_neighbors:
                bgp_underlay_config.append("  neighbor {} peer-group {}".format(neighbor, peer_group))
        if len(remote_ases_and_neighbors) == 1:
            bgp_underlay_config.insert(-(number_of_neighbors), "  neighbor {} remote-as {}".format(peer_group, next(iter(remote_ases_and_neighbors))))
        else:
            for remote_as, bgp_neighbors in remote_ases_and_neighbors.items():
                for neighbor in bgp_neighbors:
                    bgp_underlay_config.append("  neighbor {} remote-as {}".format(neighbor, remote_as))
        bgp_underlay_config.append("  redistribute connected")
        bgp_underlay_config.append("!")

        return "\n".join(bgp_underlay_config)
        
    def build_vxlan_data_plane(self, vlans_to_vnis, overlay_source__address, port=4789, overlay_source_interface="Loopback1"):
        """
        Args:
            vlans_to_vnis ( {int:int} ) --> dictionary of vlan to vni mappings, vlan is key vni is value
            port ( int ) --> port number for vxlan to run on
            source_interface ( str ) --> name of source interface

        """
        vxlan_config = []
        
        #build vxlan config
        vxlan_config.append("interface {}".format(overlay_source_interface))
        vxlan_config.append("  ip address {}".format(overlay_source__address))
        vxlan_config.append("!")

        if chipModelInfo[self.chipset]["family"] == "Sand":
            vxlan_config.append("hardware tcam")
            vxlan_config.append("system profile vxlan-routing")
            vxlan_config.append("!")

        vxlan_config.append("interface Vxlan1")
        vxlan_config.append("  vxlan source-interface {}".format(overlay_source_interface))
        vxlan_config.append("  vxlan udp-port {}".format(port))
        #Sort vlans
        vlans_to_vnis = OrderedDict(sorted(vlans_to_vnis.items()))
        for vlan, vni in vlans_to_vnis.items():
            vxlan_config.append("  vxlan vlan {} vni {}".format(vlan, vni))
        vxlan_config.append("!")

        return "\n".join(vxlan_config)

    def build_vxlan_control_plane(self, control_plane, vtep_peers=None, cvx_address=None, evpn_peers=None,
                                    asn=None, source_interface="loopback 0", role=None, evpn_model="symmetric",
                                    svi_to_address=None, mac_vrf_route_distinguisher="1.1.1.1", vrf="vrf1",
                                    vrf_route_distinguisher="1.1.1.1", vrf_route_target="1001",
                                    virtual_address_mode="ip address virtual"):
        """
        Args:
            control_plane ( str ) --> type of control plane option; options are "static", "cvx", and "evpn"
            vtep peers ( [str] ) --> Array of IP addresses
            cvx_address ( str ) --> IP address of CVX
            evpn_peers ( {str:str} ) --> dictionary of remote-ases and bgp neighbors
            asn ( int ) --> bgp asn for switch
        """
        #build vxlan_control_plane confif
        config = []
        if control_plane == "static":
            if vtep_peers is None:
                assert "Error: Static chosen as control plane and no vtep_peers provided."
            config.append("interface Vxlan1")
            for vtep in vtep_peers:
                config.append("  vxlan flood vtep {}".format(vtep))
            config.append("!")

        elif control_plane == "cvx":
            config = self.build_cvx(cvx_address)

        elif control_plane == "evpn":
            config = self.build_evpn(evpn_peers, asn=asn, source_interface=source_interface, role=role, evpn_model=evpn_model,
                            svi_to_address=svi_to_address, mac_vrf_route_distinguisher=mac_vrf_route_distinguisher, vrf=vrf,
                            vrf_route_distinguisher=vrf_route_distinguisher, vrf_route_target=vrf_route_target,
                            virtual_address_mode=virtual_address_mode)

        else:
            assert "Error: Invalid controle plane option selected.  Options are 'static', 'cvx', and 'evpn'"
            return

        return "\n".join(config)

    def build_evpn(self, evpn_peers, asn=None, source_interface="loopback 0", role=None, evpn_model=None,
                     svi_to_address=None, mac_vrf_route_distinguisher="1.1.1.1",
                     vrf="vrf1", vrf_route_distinguisher="1.1.1.1", vrf_route_target="1001",
                     virtual_address_mode="ip address virtual"):
        """
        Args:
            evpn_peers ( {str:str} ) --> dictionary of remote-ases and bgp neighbors
            asn ( int ) --> bgp asn for switch
            svi_to_address ( {int:str}) --> dictionary of vlans to virtual ip addresses
            virtual_address_mode ( str ) --> signals to use 'ip address virtual' or 'ip virtual-router address' for svi vIP
        """
        
        vrf_config = []
        interface_config = []
        bgp_config = []


        if evpn_peers is None or asn is None:
            assert "Error: EVPN chosen as control plane and either no evpn peers provided or no BGP asn provided"
            return

        if role=="leaf":
            peer_group = "SPINE-EVPN-TRANSIT"
        elif role == "spine":
            peer_group = "VTEP-EVPN-TRANSIT"
        else:
            assert "Error: No role specified. Please specify either 'spine' or 'leaf'"
            return

        #calculate number of neighbors
        number_of_neighbors = 0
        for bgp_asn, neighbors in evpn_peers.items():
            number_of_neighbors += len(neighbors)

        bgp_config.append("router bgp {}".format(asn))
        bgp_config.append("  neighbor {} peer-group".format(peer_group))
        bgp_config.append("  neighbor {} next-hop unchanged".format(peer_group))
        bgp_config.append("  neighbor {} update-source {}".format(peer_group, source_interface))
        bgp_config.append("  neighbor {} ebgp-multihop".format(peer_group))
        bgp_config.append("  neighbor {} send-community extended".format(peer_group))
        bgp_config.append("  neighbor {} maximum-routes 0".format(peer_group))

        for remote_as, bgp_neighbors in evpn_peers.items():
            for neighbor in bgp_neighbors:
                bgp_config.append("  neighbor {} peer-group {}".format(neighbor, peer_group))
        if len(evpn_peers) == 1:
            bgp_config.insert(-(number_of_neighbors), "  neighbor {} remote-as {}".format(peer_group, next(iter(evpn_peers))))
        else:
            for remote_as, bgp_neighbors in evpn_peers.items():
                for neighbor in bgp_neighbors:
                    bgp_config.append("  neighbor {} remote-as {}".format(neighbor, remote_as))
        bgp_config.append("  !")
        bgp_config.append("  address-family evpn")
        bgp_config.append("    neighbor {} activate".format(peer_group))
        bgp_config.append("  !")
        bgp_config.append("  address-family ipv4")
        bgp_config.append("    no neighbor {} activate".format(peer_group))
        bgp_config.append("  !")

        if role == "leaf":
            if evpn_model == "central":
                pass
            elif evpn_model == "symmetric" or evpn_model == "asymmetric":
                if evpn_model == "symmetric":
                    vrf_config.append("vrf instance {}".format(vrf))
                    vrf_config.append("!")
                    bgp_config.append("  vrf {}".format(vrf))
                    bgp_config.append("    rd {}:{}".format(vrf_route_distinguisher, vrf_route_target))
                    bgp_config.append("    route-target import 1:{}".format(vrf_route_target))
                    bgp_config.append("    route-target export 1:{}".format(vrf_route_target))
                    bgp_config.append("    redistribute connected")
                    bgp_config.append("    redistribute static")
                    bgp_config.append("  !")

                #Order SVIs
                svi_to_address = OrderedDict(sorted(svi_to_address.items()))
                for vlan, address in svi_to_address.items():
                    interface_config.append("interface Vlan{}".format(vlan))
                    if evpn_model == "symmetric":
                        interface_config.append("  no autostate")
                        interface_config.append("  vrf forwarding {}".format(vrf))
                    if virtual_address_mode == "ip address virtual":
                        interface_config.append("  ip address virtual {}".format(address))
                    else:
                        interface_config.append("  ip virtual-router address {}".format(address))
                    interface_config.append("!")
                    bgp_config.append("  vlan {}".format(vlan))
                    bgp_config.append("    rd {}:{}".format(mac_vrf_route_distinguisher, vlan))
                    bgp_config.append("    route-target both 1:{}".format(vlan))
                    bgp_config.append("    redistribute learned")
                    bgp_config.append("  !")

            else:
                assert "Error: Invalid evpn model.  Options are 'central', 'symmetric', and 'asymmetric'"



        evpn_config = ["\n".join(vrf_config), "\n".join(interface_config), "\n".join(bgp_config)]

        evpn_config = ["\n".join(evpn_config)]
        return evpn_config

    def build_cvx(self, cvx_address):
        config = []
        if cvx_address is None:
            assert "Error: CVX chosen as control plane and no CVX address provided"
            return
        config.append("management cvx")
        config.append("  server host {}".format(cvx_address))
        config.append("  no shutdown")
        config.append("!")
        config.append("interface Vxlan1")
        config.append("  vxlan controller-client")
        config.append("!")
        return config
        

    def order_interfaces_by_most_common_speed(self):
        """
        Returns a dictionary of interfaces ordered by most common interface speed.  
        Bandwidth values are the keys, lists of interface names are the values.
        """
        interface_speeds = {}
        ordered_interface_speeds = OrderedDict()

        for interface in self.interfaces:
            if interface["bandwidth"] == "":
                continue
            if interface["bandwidth"] in interface_speeds.keys():
                interface_speeds[interface["bandwidth"]].append(interface["interface"])
            else:
                interface_speeds[interface["bandwidth"]] = [interface["interface"]]
        for k in sorted(interface_speeds, key=lambda k: len(interface_speeds[k]), reverse=True):
            ordered_interface_speeds[k] = interface_speeds[k]
        return ordered_interface_speeds

