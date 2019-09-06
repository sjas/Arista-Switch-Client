class Switch():
    """
    Class to act as an EOS Switch object.  Uses Netmiko (SSH) or jsonrpclib (EAPI) to execute switch functions. 
    """
    def __init__(self, ip_address=None, hostname=None, username=None, password=None):
        self.ip_address = ip_address
        self.hostname = hostname
        self.username = username
        self.password = password

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