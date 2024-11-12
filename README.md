# SoftBank Mesh API RP562B Exploits API

## Overview

This repository contains a Python API to exploit known vulnerabilities on SoftBank Wi-Fi Mesh RP562B, allowing unauthenticated attackers to obtain information about devices connected through Wi-Fi (CVE-2024-47799) and authenticated attackers to execute arbitrary OS commands (CVE-2024-45827).

<img src="https://neroteam.com/blog/pages/softbank-wi-fi-mesh-rp562b/softbank-hacked-cover.jpg?m=1724043938" alt="SoftBank Mesh API RP562B Exploits API" width="600">

## Prerequisites

- Python 3.x
- Required Python packages listed in `requirements.txt`

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/0xNslabs/SoftBankMeshAPI
    cd SoftBankMeshAPI
    ```

2. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

### Configuration

Before running the script, you need to configure the `device` dictionary in `main.py` with the appropriate details:

```python
device = {
    "mesh_ip": "INSERT_YOUR_DEVICE_IP",
    "mesh_username": "user",
    "mesh_password": "RTconf01",
    "wifi_name": "ThePromisedLan",
    "wifi_password": "00000000",
}
```

## Exploiting Vulnerabilities
### Unauthenticated Access to Wi-Fi Credentials (CVE-2024-47799)
To obtain Wi-Fi credentials without authentication, use the `getWifiCreds` function:
```python
response = sbmeshAPI.getWifiCreds(device)
print(response)
```
To set Wi-Fi credentials without authentication, use the `setWifiCreds` function:
```python
response = sbmeshAPI.setWifiCreds(device)
print(response)
```

### Authenticated Remote Command Execution (CVE-2024-45827)
To execute an arbitrary OS command with authentication, use the `execTelnetRce` function:
```python
response = sbmeshAPI.execTelnetRce(device)
print(response)
```

## Write-Up
https://neroteam.com/blog/softbank-wi-fi-mesh-rp562b

## Video Proof of Concept
[![Script PoC CVE-2024-47799 Remote Command Injection](https://i.ibb.co/7gXHL9q/500px-youtube-social-play.png)](https://youtu.be/GWpFmmhtheg)

## Disclaimer
This software is intended for educational and research purposes only. Unauthorized access to computer systems is illegal and unethical. The authors and contributors of this software are not responsible for any misuse or damage caused by this software.
