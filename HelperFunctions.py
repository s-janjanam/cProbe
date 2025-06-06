# coding=utf-8
# !/usr/bin/python
from gevent import monkey
monkey.patch_all()

import time
import os
import sys
from logging import WARN, INFO, ERROR, DEBUG, CRITICAL
import json
from binascii import hexlify
from bson.objectid import ObjectId, InvalidId
from datetime import datetime
import re
import socket
from bottle import request
from simplejson import JSONDecodeError
import pwd
import errno
import traceback
import struct
import pymongo
from pymongo import MongoClient
from pymongo import errors as py_errors
from consts import Consts
import MyLogging
import bottle
from collections import namedtuple
import gevent
from gevent import subprocess
import inspect
import dpdk_devbind
from ipaddress import IPv4Network
import hashlib

def run_cmd(cmd, use_gevent=False):
    print("Running command: {}".format(cmd))
    popen = subprocess.Popen if not use_gevent else gevent.subprocess.Popen
    p = popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sout, serr = p.communicate()
    rc = p.returncode
    return rc, serr, sout


# run command and handle error
def run_cmd_e(cmd):
    try:
        rc, serr, sout = run_cmd(cmd)
        sout = sout.decode('utf8')
        serr = serr.decode('utf8')
        if rc != 0:
            raise Exception(sout + serr)
    except Exception as e:
        print("Error running cmd:{}".format(cmd))
        print("{}".format(str(e)))
    return sout


def tar_files(tarfile_name, file_info, use_gevent=False):
    # file_info = {path: [file_list]}
    tar_cmd = "tar czf {} ".format(tarfile_name)
    for path, file_list in file_info.items():
        tar_cmd += "-C {} {} ".format(path, " ".join(file_list))
    return run_cmd(tar_cmd, use_gevent=use_gevent)

def process_is_running(process):
    process = upstart_to_systemd_process_name(process)
    if process is None:
        return False
    status_cmd = "systemctl is-active {}".format(process)
    p = subprocess.Popen(status_cmd,
                         shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sout, serr = p.communicate()
    if 'inactive' in sout:
        return False
    elif 'active' in sout:
        return True
    else:
        return False


def processes_are_running(processes_list):
    for process in processes_list:
        if not process_is_running(process):
            return False
    return True

def control_process(process, action):
    rc = 1
    my_logger.debug("trying to {} the {} process".format(action, process))
    if action not in ['start', 'stop', 'restart', 'enable', 'disable']:
        my_logger.error("The action: {} is not valid for systemd operations".format(action))
        return rc
    process = upstart_to_systemd_process_name(process)
    if process is None:
        return rc
    my_cmd = "systemctl {} {} ".format(action, process)
    p = subprocess.Popen(my_cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)
    sout, serr = p.communicate()
    rc = p.returncode
    if rc != 0 or serr != '':
        my_logger.debug("control process {}: RC={} stderr: {}".format(p, rc, serr))
    return rc

def rm_files(f_name, quiet=False):
    rv = {"status": "success"}
    try:
        os.remove(f_name)
    except OSError:
        # the PCAP file may not exist
        pass
    base_name, ext = os.path.splitext(f_name)
    while 'pcap' not in ext:
        # need to extract from .cpcap.5 or .pcap.2 or .pcap.Z.2 :
        base_name, ext = os.path.splitext(base_name)
    extensions = ["nat", "nat.db", "ind", "ind.db", "cnt", "flow", "sess", "srv", "srv.db", "map", "map.db", "eps"]
    for ext in extensions:
        try:
            f_name = "{}.{}".format(base_name, ext)
            os.remove(f_name)
        except OSError as e:
            pass
    return rv


def remove_file(f_name, ignore_missing=False):
    if not os.path.exists(f_name):
        return
    try:
        os.remove(f_name)
    except Exception as e:
        print("Failed to remove file: {} {}".format(f_name, str(e)))


# remove files in directory , non-recursive
def rm_files_in_dir(d_name, skip_files=[]):
    rm_list = []
    for item in os.listdir(d_name):
        item_path = os.path.join(d_name, item)
        if os.path.isfile(item_path) and item not in skip_files:
            try:
                os.remove(item_path)
                rm_list.append(item_path)
            except Exception as e:
                print("Failed to remove {}, {}".format(item_path, e))
    return rm_list


# makedirs with ignore option
def makedirs(d_name, exist_ok=False):
    try:
        if not os.path.isdir(d_name) or not exist_ok:
            os.makedirs(d_name)
    except Exception as e:
        print("Failed to create directory {} - {}".format(d_name, e))


if __name__ == "__main__":
    sys.exit("not supposed to run as a main module")
else:
    init_db_and_logger(__name__)
