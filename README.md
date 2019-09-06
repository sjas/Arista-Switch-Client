# Arista-Switch-Client

Quick python object to send commands to Arista switches.

Sends commands via Arista's EAPI using jsonrpclib or via SSH using netmiko

Switch.send_commands_via_eapi(cmds) uses the jsonrpclib Server object to execute commands on a switch

Switch.send_commands_via_netmiko(cmds) uses the netmiko python library to execute commands on a switch

Switch.send_commands(cmds, method=str) will by default use eapi (method="eapi") to send commands but can use ssh if you specify "ssh" in the method variable.


1.  Install the project
     
    pip install AristaSwitchClient
    
2.  In a python file

    from EOS.Switch import Switch
    
    switch = Switch(ip_address="10.0.0.1", username="arista", password="arista")
    
    print(switch.send_commands("show version"))
    
    
