#!/usr/bin/python3

import os
import click
import requests
import urllib3
import hashlib
import hmac
import base64
import uuid
import time
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime, timedelta

# -----------------------------
# Constants / Secrets
# -----------------------------
access_key = '4d11b6b9d5ea4d19a829adbb9714b057'
secret = '6ed7d97f3e73467f8a5bab90b577ba4c'

REQUEST_TIMEOUT = 60
DOWNLOAD_RETRIES = 3
DOWNLOAD_SLEEP = 1

nonce = str(uuid.uuid1())
now = str(int(time.time()))

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -----------------------------
# Helpers
# -----------------------------
def content_md5(content):
    return base64.b64encode(hashlib.md5(content.encode('UTF-8')).digest()).decode('UTF-8')

def signature(content, endpoint):
    payload = (content_md5(content) + '\n' + now + '\n' + nonce + '\n' + endpoint).encode('UTF-8')
    return hmac.new(secret.encode('UTF-8'), payload, hashlib.sha1).digest().hex()

def x_authorization(content, endpoint):
    return f"Timestamp={now}, Nonce={nonce}, AccessKey={access_key}, Signature={signature(content, endpoint)}"

def get_config():
    try:
        with open(os.path.expanduser('~/.tapo-cli/.config'), 'r') as f:
            config = json.loads(f.read())
        return (
            config['token'],
            config['email'],
            config['appServerUrl'],
            'https://euw1-app-tapo-care.i.tplinknbu.com'
        )
    except Exception:
        print("❌ Please login first.")
        exit(1)

def error(obj):
    print("❌ API Error:", obj)
    exit(obj.get('error_code', 1))

def headers_get(token):
    return {
        'Authorization': 'ut|' + token,
        'X-App-Name': 'TP-Link_Tapo_Android'
    }

def headers_post(content, endpoint):
    return {
        'Content-Md5': content_md5(content),
        'X-Authorization': x_authorization(content, endpoint),
        'Content-Type': 'application/json; charset=UTF-8',
        'User-Agent': 'Tapo CameraClient Android'
    }

def get(url, params, headers):
    r = requests.get(url, params=params, headers=headers, verify=False, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()

def post(url, data, headers):
    r = requests.post(url, data=data, headers=headers, verify=False, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()

# -----------------------------
# Safe Download (RETRY + TIMEOUT)
# -----------------------------
def download(url, key_b64, file_path, file_name):
    os.makedirs(file_path, exist_ok=True)

    for attempt in range(1, DOWNLOAD_RETRIES + 1):
        try:
            res = requests.get(url, timeout=REQUEST_TIMEOUT)
            res.raise_for_status()
            content = res.content

            if key_b64:
                key = base64.b64decode(key_b64)
                iv = content[:16]
                enc_data = content[16:]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                content = unpad(cipher.decrypt(enc_data), AES.block_size)

            with open(os.path.join(file_path, file_name), 'wb') as f:
                f.write(content)

            return

        except Exception as e:
            print(f"⚠️ Download failed ({attempt}/{DOWNLOAD_RETRIES}): {file_name}")
            print(f"   Reason: {e}")
            time.sleep(5)

    print(f"❌ Skipped after retries: {file_name}")

# -----------------------------
# API Wrappers
# -----------------------------
def probe_endpoint_get(params, endpoint):
    token, _, _, app_server_url = get_config()
    return get(app_server_url + endpoint, params, headers_get(token))

def probe_endpoint_post(content, endpoint):
    token, _, app_server_url, _ = get_config()
    res = post(app_server_url + endpoint + '?token=' + token, content, headers_post(content, endpoint))
    if res['error_code'] != 0:
        error(res)
    return res['result']

# -----------------------------
# CLI
# -----------------------------
@click.group()
def tapo():
    """Tapo CLI"""
    pass

# -----------------------------
# LOGIN
# -----------------------------
@click.command()
@click.option('--username', prompt="Username")
@click.option('--password', prompt="Password", hide_input=True)
def login(username, password):
    """Authenticates a user towards the TP-Link Tapo Cloud."""
    terminal_uuid = str(uuid.uuid1()).replace('-', '').upper()

    url = 'https://n-wap-gw.tplinkcloud.com/api/v2/account/login'
    content = {
        "appType": "TP-Link_Tapo_Android",
        "appVersion": "2.12.705",
        "cloudUserName": username,
        "cloudPassword": password,
        "platform": "Android 12",
        "refreshTokenNeeded": False,
        "terminalMeta": "1",
        "terminalName": "Tapo CLI",
        "terminalUUID": terminal_uuid
    }

    payload = json.dumps(content)
    res = post(url, payload, headers_post(payload, '/api/v2/account/login'))

    if res['error_code'] != 0:
        error(res)

    # MFA handling (unchanged, REQUIRED)
    if 'MFAProcessId' in res['result']:
        mfa_process_id = res['result']['MFAProcessId']

        url = 'https://n-wap-gw.tplinkcloud.com/api/v2/account/getPushVC4TerminalMFA'
        payload = json.dumps({
            "appType": "TP-Link_Tapo_Android",
            "cloudUserName": username,
            "cloudPassword": password,
            "terminalUUID": terminal_uuid
        })

        res = post(url, payload, headers_post(payload, '/api/v2/account/getPushVC4TerminalMFA'))
        if res['error_code'] != 0:
            error(res)

        print("📱 Check your Tapo app for the MFA code")
        mfa_code = input("MFA Code: ").strip()

        url = 'https://n-wap-gw.tplinkcloud.com/api/v2/account/checkMFACodeAndLogin'
        payload = json.dumps({
            "appType": "TP-Link_Tapo_Android",
            "cloudUserName": username,
            "code": mfa_code,
            "MFAProcessId": mfa_process_id,
            "MFAType": 1,
            "terminalBindEnabled": True
        })

        res = post(url, payload, headers_post(payload, '/api/v2/account/checkMFACodeAndLogin'))
        if res['error_code'] != 0:
            error(res)

    os.makedirs(os.path.expanduser('~/.tapo-cli'), exist_ok=True)
    with open(os.path.expanduser('~/.tapo-cli/.config'), 'w') as f:
        json.dump(res['result'], f, indent=2)

    print("✅ Login successful")

# -----------------------------
# DOWNLOAD VIDEOS (DATE RANGE)
# -----------------------------
@click.command()
@click.option('--start', prompt="Start date (YYYY-MM-DD)")
@click.option('--end', prompt="End date (YYYY-MM-DD)")
@click.option('--path', default="~/", prompt="Path")
@click.option('--overwrite', default=0, type=int)
def download_videos(start, end, path, overwrite):
    path = os.path.expanduser(path.rstrip('/') + '/')

    devs = probe_endpoint_post(
        '{"deviceTypeList":["SMART.IPCAMERA"],"index":0,"limit":20}',
        '/api/v2/common/getDeviceListByPage'
    )

    start_date = datetime.strptime(start, '%Y-%m-%d')
    end_date = datetime.strptime(end, '%Y-%m-%d')

    for dev in devs['deviceList']:
        print(f"\n📷 {dev['alias']}")

        day = start_date
        while day <= end_date:
            params = (
                f"deviceId={dev['deviceId']}"
                f"&page=0&pageSize=3000&order=desc"
                f"&startTime={day.strftime('%Y-%m-%d 00:00:00')}"
                f"&endTime={day.strftime('%Y-%m-%d 23:59:59')}"
            )

            videos = probe_endpoint_get(params, '/v2/videos/list')
            total = videos.get('total', 0)
            print(f"  {day.date()} → {total} videos")

            for video in videos.get('index', []):
                v = video['video'][0]
                url = v['uri']
                key = v.get('decryptionInfo', {}).get('key')

                file_dir = f"{path}{dev['alias']}/{day.strftime('%Y-%m-%d')}/"
                file_name = video['eventLocalTime'].replace(':', '-') + '.mp4'

                if os.path.exists(file_dir + file_name) and overwrite == 0:
                    continue

                print("   ↓", file_name)
                download(url, key, file_dir, file_name)
                time.sleep(DOWNLOAD_SLEEP)

            day += timedelta(days=1)

# -----------------------------
# Register
# -----------------------------
tapo.add_command(login)
tapo.add_command(download_videos)

if __name__ == '__main__':
    tapo()