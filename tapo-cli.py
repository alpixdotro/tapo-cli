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
import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime, timedelta

# Secrets extracted from the .apk
access_key = '4d11b6b9d5ea4d19a829adbb9714b057'
secret = '6ed7d97f3e73467f8a5bab90b577ba4c'

# Every request needs a uuid nonce and time
nonce = str(uuid.uuid1())
now = str(int(time.time()))

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def content_md5(content):
    return base64.b64encode(hashlib.md5(content.encode('UTF-8')).digest()).decode('UTF-8')

def signature(content, endpoint):
    payload = (content_md5(content) + '\n' + now + '\n' + nonce + '\n' + endpoint).encode('UTF-8')
    return hmac.new(secret.encode('UTF-8'), payload, hashlib.sha1).digest().hex()

def x_authorization(content, endpoint):
    return 'Timestamp=' + now + ', Nonce=' + nonce + ', AccessKey=' + access_key + ', Signature=' + signature(content, endpoint)

def get_config():
    try:
        file = open(os.path.expanduser('~') + '/.tapo-cli/.config', 'r')
        config = json.loads(file.read())
        token = config['token']
        email = config['email']
        app_server_url_post = config['appServerUrl']
        return token, email, app_server_url_post, 'https://euw1-app-tapo-care.i.tplinknbu.com'
    except:
        print('Please login first.')
        exit(1)

def error(obj):
    print('Something went wrong:')
    print(obj)
    if 'error_code' in obj:
        exit(obj['error_code'])
    else:
        exit(1)

def headers_get(token):
    return {
        'Authorization' : 'ut|' + token,
        'X-App-Name' : 'TP-Link_Tapo_Android'
    }

def headers_post(content, endpoint):
    return {
        'Content-Md5' : content_md5(content),
        'X-Authorization' : x_authorization(content, endpoint),
        'Content-Type': 'application/json; charset=UTF-8',
        'User-Agent': 'Tapo CameraClient Android' if '/api/v2/common/passthrough' in endpoint else 'okhttp/3.12.13'
    }

def get(url, params, headers):
    return json.loads(requests.get(url, params = params, headers = headers, verify = False).text)

def post(url, data, headers):
    return json.loads(requests.post(url, data = data, headers = headers, verify = False).text)

def download(url, key_b64, file_path, file_name):
    if not os.path.exists(file_path): os.makedirs(file_path)
    res = requests.get(url)
    content = res.content
    if key_b64:
        key = base64.b64decode(key_b64)
        iv = content[:16]
        enc_data = content[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec_content = unpad(cipher.decrypt(enc_data), AES.block_size)
    else:
        dec_content = content
    with open(os.path.join(file_path, file_name), 'wb') as file:
        file.write(dec_content)

def probe_endpoint_get(params, endpoint):
    token, null, null, app_server_url_get = get_config()
    url = app_server_url_get + endpoint
    res = get(url, params, headers_get(token))
    return res

def probe_endpoint_post(content, endpoint):
    token, null, app_server_url_post, null = get_config()
    url = app_server_url_post + endpoint + '?token=' + token
    res = post(url, content, headers_post(content, endpoint))
    if (res['error_code'] != 0):
        error(res)
    else:
        return res['result']

@click.group()
def tapo():
    """Command-line application for batch-downloading your videos from the Tapo TP-Link Cloud."""
    pass

@click.command()
@click.option('--username', default="email@example.com", prompt="Username", help='Your Tapo TP-Link username.')
@click.option('--password', default="H0p3ful1yN0tY0urP@$$w0rd", prompt="Password", help='Your Tapo TP-Link password.')
def login(username, password):
    """Authenticates a user towards the TP-Link Tapo Cloud."""
    terminal_uuid = str(uuid.uuid1()).replace('-','').upper()
    url = 'https://n-wap-gw.tplinkcloud.com/api/v2/account/login'
    content = {"appType":"TP-Link_Tapo_Android","appVersion":"2.12.705","cloudPassword":password,"cloudUserName":username,"platform":"Android 12","refreshTokenNeeded":False,"terminalMeta":"1","terminalName":"Tapo CLI","terminalUUID":terminal_uuid}
    content = json.dumps(content)
    res = post(url, content, headers_post(content, '/api/v2/account/login'))
    if (res['error_code'] != 0):
        error(res)
    config = json.dumps(res['result'], indent = 4)
    if 'MFAProcessId' in config:
        mfa_process_id = res['result']['MFAProcessId']
        url = 'https://n-wap-gw.tplinkcloud.com/api/v2/account/getPushVC4TerminalMFA'
        content = {"appType":"TP-Link_Tapo_Android","cloudPassword":password,"cloudUserName":username,"terminalUUID":terminal_uuid}
        content = json.dumps(content)
        res = post(url, content, headers_post(content, '/api/v2/account/getPushVC4TerminalMFA'))
        if (res['error_code'] != 0):
            error(res) 
        print('Check your Tapo App for the MFA code!')
        mfa_code = str(input('MFA Code (no spaces or dashes): '))
        url = 'https://n-wap-gw.tplinkcloud.com/api/v2/account/checkMFACodeAndLogin'
        content = {"appType":"TP-Link_Tapo_Android","cloudUserName":username,"code":mfa_code,"MFAProcessId":mfa_process_id,"MFAType":1,"terminalBindEnabled":True}
        content = json.dumps(content)
        res = post(url, content, headers_post(content, '/api/v2/account/checkMFACodeAndLogin'))
        if (res['error_code'] != 0):
            error(res)
        config = json.dumps(res['result'], indent = 4)
    file_path = os.path.expanduser('~') + '/.tapo-cli/'
    file_name = '.config'
    if not os.path.exists(file_path): os.makedirs(file_path)
    with open(file_path + file_name, 'w+') as file:
        file.write(config)
    print('Access token saved in ' + file_path + file_name)

# -----------------------------
# List videos with custom date range
# -----------------------------
@click.command()
@click.option('--start', prompt="Start date (YYYY-MM-DD)", help='Start date (YYYY-MM-DD)')
@click.option('--end', prompt="End date (YYYY-MM-DD)", help='End date (YYYY-MM-DD)')
def list_videos(start, end):
    """Lists videos for a specific date range."""
    get_config()
    endpoint = '/api/v2/common/getDeviceListByPage'
    content = '{"deviceTypeList":["SMART.IPCAMERA"],"index":0,"limit":20}'
    devs = probe_endpoint_post(content, endpoint)
    endpoint = '/v2/videos/list'

    start_date = datetime.strptime(start, '%Y-%m-%d')
    end_date = datetime.strptime(end, '%Y-%m-%d')
    delta = end_date - start_date
    days_list = [start_date + timedelta(days=i) for i in range(delta.days + 1)]

    for dev in devs['deviceList']:
        print(f'\nProcessing device: {dev["alias"]}')
        for day in days_list:
            start_time = day.strftime('%Y-%m-%d 00:00:00')
            end_time = day.strftime('%Y-%m-%d 23:59:59')
            params = f'deviceId={dev["deviceId"]}&page=0&pageSize=3000&order=desc&startTime={start_time}&endTime={end_time}'
            videos = probe_endpoint_get(params, endpoint)
            total = videos.get('total', 0)
            print(f'Found {total} videos for {dev["alias"]} on {day.strftime("%Y-%m-%d")}')
            for video in videos.get('index', []):
                print(video['eventLocalTime'], end=", ")
            if total > 0: print('')

# -----------------------------
# Download videos with custom date range
# -----------------------------
@click.command()
@click.option('--start', prompt="Start date (YYYY-MM-DD)", help='Start date (YYYY-MM-DD)')
@click.option('--end', prompt="End date (YYYY-MM-DD)", help='End date (YYYY-MM-DD)')
@click.option('--path', default="~/", prompt="Path", help='Path where videos will be downloaded.')
@click.option('--overwrite', default=0, prompt="Overwrite", help='Overwrite files if already exist.')
def download_videos(start, end, path, overwrite):
    """Downloads videos for a specific date range."""
    get_config()
    path = path if path[-1] == '/' else path + '/'
    path = os.path.expanduser(path)
    endpoint = '/api/v2/common/getDeviceListByPage'
    content = '{"deviceTypeList":["SMART.IPCAMERA"],"index":0,"limit":20}'
    devs = probe_endpoint_post(content, endpoint)
    endpoint = '/v2/videos/list'

    start_date = datetime.strptime(start, '%Y-%m-%d')
    end_date = datetime.strptime(end, '%Y-%m-%d')
    delta = end_date - start_date
    days_list = [start_date + timedelta(days=i) for i in range(delta.days + 1)]

    for dev in devs['deviceList']:
        print(f'\nProcessing device: {dev["alias"]}')
        for day in days_list:
            start_time = day.strftime('%Y-%m-%d 00:00:00')
            end_time = day.strftime('%Y-%m-%d 23:59:59')
            params = f'deviceId={dev["deviceId"]}&page=0&pageSize=3000&order=desc&startTime={start_time}&endTime={end_time}'
            videos = probe_endpoint_get(params, endpoint)
            total = videos.get('total', 0)
            print(f'Found {total} videos for {dev["alias"]} on {day.strftime("%Y-%m-%d")}')

            for video in videos.get('index', []):
                url = video['video'][0]['uri']
                key_b64 = False
                if 'encryptionMethod' in video['video'][0]:
                    method = video['video'][0]['encryptionMethod']
                    if method != "AES-128-CBC":
                        print(f"Unsupported encryption method: {method}. Quitting...")
                        exit(1)
                    key_b64 = video['video'][0]['decryptionInfo']['key']

                file_path = path + dev['alias'] + '/' + day.strftime('%Y-%m-%d') + '/'
                file_name = video['eventLocalTime'].replace(':','-') + '.mp4'

                if os.path.exists(file_path + file_name) and overwrite == 0:
                    print('Already exists ' + file_path + file_name)    
                else:
                    print('Downloading to ' + file_path + file_name)
                    download(url, key_b64, file_path, file_name)

# -----------------------------
# Register commands
# -----------------------------
tapo.add_command(login, 'login')
tapo.add_command(list_videos, 'list-videos')
tapo.add_command(download_videos, 'download-videos')

if __name__ == '__main__':
    tapo()