#!/usr/bin/env python3
# coding=utf-8

"""
    Helper functions for cProbe
    (No MongoDB required; uses config/config.json for settings)
    © 2007-2025 cPacket Networks Inc. All Rights Reserved.
"""

import os
import sys
import time
import json
import re
import socket
import struct
import traceback
from datetime import datetime

# ---- CONFIG FILE HELPERS ----

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config', 'config.json')

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2)

def get_setting(*keys, default=None):
    config = load_config()
    val = config
    for k in keys:
        val = val.get(k, None)
        if val is None:
            return default
    return val

def set_setting(value, *keys):
    config = load_config()
    obj = config
    for k in keys[:-1]:
        obj = obj.setdefault(k, {})
    obj[keys[-1]] = value
    save_config(config)

# ---- LOGGING ----

class MyLogger:
    def __init__(self, name, logfile=None, console=True, level=2, **kwargs):
        self.name = name
        self.console = console
        self.level = level  # 1: ERROR, 2: WARNING, 3: INFO, 4: DEBUG
        self.logfile = logfile

    def _log(self, level_name, msg):
        ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        fullmsg = f"[{ts}][{self.name}][{level_name}] {msg}"
        if self.console:
            print(fullmsg)
        if self.logfile:
            with open(self.logfile, 'a') as f:
                f.write(fullmsg + '\n')

    def debug(self, msg):
        if self.level >= 4:
            self._log('DEBUG', msg)

    def info(self, msg):
        if self.level >= 3:
            self._log('INFO', msg)

    def warn(self, msg):
        if self.level >= 2:
            self._log('WARNING', msg)

    def error(self, msg):
        if self.level >= 1:
            self._log('ERROR', msg)

# ---- GENERAL HELPERS ----

def run_cmd(cmd):
    import subprocess
    print("Running command:", cmd)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sout, serr = p.communicate()
    rc = p.returncode
    return rc, serr.decode('utf-8'), sout.decode('utf-8')

def tar_files(tarfile_name, file_info):
    tar_cmd = f"tar czf {tarfile_name} "
    for path, file_list in file_info.items():
        tar_cmd += f"-C {path} {' '.join(file_list)} "
    return run_cmd(tar_cmd)

def is_string_simple(my_str, whitespace=False, max_len=255, min_len=0):
    pattern = "^[A-Za-z0-9_-]*$"
    if whitespace:
        pattern = "^[A-Za-z 0-9_-]*$"
    return (my_str is not None and re.match(pattern, my_str)
            and (max_len >= len(my_str) >= min_len))

def ip_to_int(addr):
    if addr is None:
        return 0
    try:
        return struct.unpack("!I", socket.inet_aton(addr))[0]
    except socket.error:
        return 0

def int_to_ip4(ip):
    try:
        packed_ip = struct.pack('!L', ip % 2 ** 32)
        return socket.inet_ntoa(packed_ip)
    except Exception:
        return '0.0.0.0'

def is_valid_ip(addr):
    try:
        socket.inet_pton(socket.AF_INET, addr)
        return True
    except Exception:
        return False

def is_valid_ip6(addr):
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except Exception:
        return False

def is_valid_port(p):
    try:
        port = int(p)
        return 0 <= port <= 65535
    except Exception:
        return False

def is_valid_hostname(hname):
    if len(hname) > 255:
        return False
    if hname[-1] == ".":
        hname = hname[:-1]
    ok = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(ok.match(x) for x in hname.split("."))

def makedirs(d_name, exist_ok=False):
    try:
        os.makedirs(d_name, exist_ok=exist_ok)
    except Exception as e:
        print(f"Failed to create directory {d_name} - {e}")

def read_str_from_file(f_name):
    try:
        with open(f_name, 'r') as f:
            return f.read().strip()
    except Exception:
        return None

def read_int_from_file(f_name):
    try:
        with open(f_name, 'r') as f:
            return int(f.read().strip())
    except Exception:
        return -1

def rm_files(f_name):
    rv = {"status": "success"}
    try:
        os.remove(f_name)
    except OSError:
        pass
    return rv

def rm_files_in_dir(d_name, skip_files=[]):
    rm_list = []
    for item in os.listdir(d_name):
        item_path = os.path.join(d_name, item)
        if os.path.isfile(item_path) and item not in skip_files:
            try:
                os.remove(item_path)
                rm_list.append(item_path)
            except Exception as e:
                print(f"Failed to remove {item_path}, {e}")
    return rm_list

def get_base_image():
    # This function can read a file or just return a default value
    return 1804

def baseimage():
    return get_base_image()

# ---- Example: Get/Set Configurations ----

def get_capture_mode():
    # Example: get 'capture_mode' from config
    return get_setting('nprobe', 'general', 'capture_mode', default=None)

def set_capture_mode(mode):
    set_setting(mode, 'nprobe', 'general', 'capture_mode')

# ---- Add more helpers as needed ----

if __name__ == "__main__":
    sys.exit("Not supposed to run as a main module")
