import requests, json, re
#Disables no certificate CVP warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CVP():
    """
    Class to act as a CVP object.  Leverages REST API to execute CVP functions. 
    """
    def __init__(self, ip_address, username, password):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.cvp_sesh = None

    def login(self):
        """
        Returns a cvp session
        """
        payload = json.dumps({"userID": self.username, "password": self.password})
        self.cvp_sesh = requests.Session()
        self.cvp_sesh.post("https://{}/cvpservice/login/authenticate.do".format(self.ip_address), data=payload, verify=False)
        return self.cvp_sesh

    def logout(self):
        """
        Logs out fof a cvp session
        """
        self.cvp_sesh.post("https://{}/cvpservice/login/logout.do".format(self.ip_address), verify=False)
        return self.cvp_sesh

    def getInventory(self, provisioned=False):
        """
        Returns the inventory

            provisioned ( bool ): Flag that will signal whether to retrieve the entire inventory or just provisioned devices

        """
        if provisioned == True:
            provisioned = "true"
        else:
            provisioned = "false"
        response = self.cvp_sesh.get("https://{}/cvpservice/inventory/devices?provisioned={}".format(self.ip_address, provisioned), verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            print("Error retrieving inventory.")
            print(response.text)
            return None