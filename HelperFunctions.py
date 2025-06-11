# coding=utf-8
# !/usr/bin/python

"""
    This module implements various helper functions

    © 2007- 2014  cPacket Networks Inc. All Rights Reserved.
"""
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
from ipaddress import IPv4Network
import hashlib

bur_db = None
my_logger = None
files_db = None
base_image = None


def detect_virtual():
    # check if we are running inside a VM and which vm it is.
    # Returns None if it's not a VM
    # print("Detecting VM type baseimage: {}".format(baseimage()))
    if baseimage() == 1804:
        status_cmd = "systemd-detect-virt"
        p = subprocess.Popen(status_cmd,
                             shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sout, serr = p.communicate()
        rc = p.returncode
        if rc != 0 or serr != '':
            my_logger.debug("Not running in a VM: ({})".format(serr))
            return None
        else:
            sout = sout.rstrip("\n\r")
            my_logger.debug("Detected VM: \"{}\"".format(sout))
            return sout
    else:
        my_logger.debug("Base image is: {} - can't be a VM".format(baseimage()))
        return None


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


def get_capture_mode():
    system_settings = my_db().system_settings.find_one()
    capture_mode = None
    if system_settings:
        capture_mode = system_settings.get('capture_mode')
    return capture_mode

def upstart_to_systemd_process_name(process):
    capture_mode = get_capture_mode()

    if 'mongod' in process:
        process = 'mongodb'
    elif 'ntp' in process:
        process = 'chrony'
    elif 'pcap' in process:
        process = process.replace('-', '@')

    if capture_mode in [None, 'myricom', 'cprobe', 'libpcap']:
        if 'dpdk_snf' in process:
            process = 'cstor_snf'
            if capture_mode == 'cprobe':
                my_logger.error("Unexpected action to handle dpdk_snf in cProbe mode")
    elif capture_mode == 'dpdk':
        if 'cstor_snf' in process:
            process = 'dpdk_snf'

    if process not in Consts.SYSD_PROCESSES + Consts.CPROBE_PROCESSES:
        my_logger.error("The process: {} is not valid for control".format(process))
        return None
    return process


def process_is_running(process):
    if baseimage() == 1804:
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
    else:
        my_logger.debug("Base image is: {} - cant check {} is running".format(baseimage(), process))


def processes_are_running(processes_list):
    for process in processes_list:
        if not process_is_running(process):
            return False
    return True


def process_is_enabled(process):
    if baseimage() == 1804:
        process = upstart_to_systemd_process_name(process)
        if process is None:
            return False
        status_cmd = "systemctl is-enabled {}".format(process)
        p = subprocess.Popen(status_cmd,
                             shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sout, serr = p.communicate()
        if 'disabled' in sout:
            return False
        elif 'enabled' in sout:
            return True
        else:
            return False
    else:
        my_logger.debug("Base image is: {} - cant check {} is enabled".format(baseimage(), process))
        return False


def control_process(process, action):
    rc = 1
    my_logger.debug("trying to {} the {} process".format(action, process))
    if baseimage() == 1804:
        if action not in ['start', 'stop', 'restart', 'enable', 'disable']:
            my_logger.error("The action: {} is not valid for systemd operations".format(action))
            return rc
        process = upstart_to_systemd_process_name(process)
        if process is None:
            return rc
        my_cmd = "systemctl {} {} ".format(action, process)
    else:
        my_logger.error("Unsupported baseimage : {}".format(baseimage()))
        return rc
    p = subprocess.Popen(my_cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)
    sout, serr = p.communicate()
    rc = p.returncode
    if rc != 0 or serr != '':
        my_logger.debug("control process {}: RC={} stderr: {}".format(p, rc, serr))
    return rc


def _p2f(x):
    try:
        n = re.findall('(\d+\.?\d*)%\S*', x)
    except TypeError:
        # already a number
        return x

    if len(n) > 0:
        f = float(n[0]) / 100
    else:
        # maybe they passed the number as decimal fraction
        try:
            f = float(x)
        except ValueError:
            return None
    return f


def extract_ids_from_path(path):
    """
    Extracts the recording id, group id and job name and username from a full path
    for now we return the recording_id only

    We need to support legacy directory names that ended with a recording_id and new path names that end with TS
    :param path:
    :return:
    """
    rv = {
        'recording_id': None,
        'new_path': False,
        'group_id': None,
        'job_name': None,
        'username': None,
        'drive': None,
    }

    (root, ext) = os.path.splitext(path)
    if not ext == '':
        (path, f_name) = os.path.split(path)

    (path, leaf) = os.path.split(path)
    try:
        ts = int(leaf)
        assert 100 > ts >= 0, "the directory name doesn't make sense"
        rv['new_path'] = True
    except ValueError:
        try:
            rv['recording_id'] = leaf
            b = ObjectId(rv['recording_id'])
        except InvalidId:
            return None
    if rv['recording_id'] is None:
        (path, rv['recording_id']) = os.path.split(path)
        try:
            b = ObjectId(rv['recording_id'])
        except InvalidId:
            return None
    (path, rv['group_id']) = os.path.split(path)
    try:
        b = ObjectId(rv['group_id'])
    except InvalidId:
        return None
    (path, rv['job_name']) = os.path.split(path)
    if rv['job_name'] == '':
        return None
    (path, username) = os.path.split(path)
    if rv['username'] == '':
        return None
    (path, rv['drive']) = os.path.split(path)
    if rv['drive'] == '':
        return None
    (path, media) = os.path.split(path)
    if media == '':
        return None
    # t = re.findall('time_(\d+).*', f_name)
    return rv


def files_size(from_time, to_time, recording_id=None):
    """
    Calculates the size on disk of the files between start and end times
    :return:
    """
    try:
        from_time = int(from_time)
        to_time = int(to_time)
        if from_time > to_time:
            to_time = max(from_time, time.time())
    except TypeError:
        to_time = max(from_time, time.time())

    total_size = 0
    last_size = 0
    count = 0
    recordings = []
    if recording_id is None:
        c_names = my_files_db().collection_names(include_system_collections=False)
        for c in c_names:
            recordings.append(c)
    else:
        recordings.append(str(recording_id))
    for r in recordings:
        try:
            f_collection = my_files_db()[r]
            cursor = f_collection.find(
                    {"$and": [
                        {"time": {"$gte": from_time}},
                        {"time": {"$lt": to_time}}
                    ]})
            count += cursor.count()
            for c in cursor:
                total_size += c.get('size', 0)
                if c.get('time') == to_time - 1:
                    last_size = c.get('size', 0)
        except (AttributeError, IndexError):
            my_logger.debug("Request for out of range time")
            pass

    rsp = {
        'files': [],
        'totalSize': total_size,
        'fileCount': count,
        'lastSpeed': 8 * last_size / 1
    }
    return rsp


class MyJsonEncoder(json.JSONEncoder):
    """
    JSON encoder used to encode ObjectId from MongoDB
    """

    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return str(o)
        if o is None:
            return ''
        return json.JSONEncoder.default(self, o)

        # if hasattr(obj, 'isoformat'):
        # return obj.isoformat()


def is_string_simple(my_str, whitespace=False, max_len=255, min_len=0):
    """
    Helper function to check that the string has alphanumeric and numbers and dashes only
    :param my_str: string to check
    :type: str
    :return: True if it's a simple string else False
    """
    pattern = "^[A-Za-z0-9_-]*$"
    if whitespace:
        pattern = "^[A-Za-z 0-9_-]*$"

    if my_str is not None and re.match(pattern, my_str) and (max_len >= len(my_str) >= min_len):
        return True
    else:
        return False


def extract_field(field, simple_string=True):
    """
    Helper function to extract a field from the query or form and check that it's a simple string
    :param field: string that is the field name
    :return:
    """
    try:
        ret = request.json.get(field)
    except (JSONDecodeError, AttributeError):
        ret = None
    if ret is None:
        ret = request.forms.get(field)
        if ret is None or ret == '':
            ret = request.query.get(field)
            if ret is None or ret == '':
                return None
    if simple_string:
        if not is_string_simple(ret):
            return None
    return ret


def log_and_abort(err_code, err_msg, tb=False):
    """
    A utility function to log the error and abort the bottle operation
    :param err_code:
    :param err_msg:
    :return:
    """
    if tb:
        traceback.print_stack(limit=6)
    my_logger.warn(err_msg)
    # bottle.abort(err_code, err_msg)
    raise bottle.HTTPResponse(status=err_code, body=err_msg)


def epoch_to_sec(epoch_time):
    resolution = "sec"
    if epoch_time > 1.00e17:
        # assume these are nanosecond
        resolution = "ns"
        epoch_time /= 1e9
    if epoch_time > 1.00e14:
        # assume these are microseconds
        resolution = "us"
        epoch_time /= 1e6
    elif epoch_time > 1.00e11:
        # assume these are milliseconds
        resolution = "ms"
        epoch_time /= 1e3
    else:
        # these are seconds
        pass
    return epoch_time, resolution


def parse_start_end_times():
    resolution = "sec"
    start_time = extract_parameter('startTime', ParameterType.float, min_val=0, max_val=sys.maxint).value
    if start_time is not None:
        start_time, resolution = epoch_to_sec(start_time)
    else:
        start_time = time.time() - 5
    end_time = extract_parameter('endTime', ParameterType.float, min_val=0, max_val=sys.maxint).value
    if end_time is not None:
        end_time, resolution = epoch_to_sec(end_time)
    else:
        end_time = time.time()

    if end_time < start_time:
        tmp_time = end_time
        end_time = start_time
        start_time = tmp_time
    my_logger.debug("start time: {} end time: {} original resolution: {}".format(
        time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(start_time)),
        time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(end_time)),
        resolution))
    return start_time, end_time


class ParameterType:
    string, safeString, safeStringWithWhiteSpace, objectId, int, \
    posixtime, bool, float, percent, ip, \
    path, debugLevel, list = range(13)


def extract_parameter(field, param_type=ParameterType.safeString, allowGet=True,
                      min_val=0, max_val=None, allowWhiteSpace=False, missingParameterStatus=400):
    Parameter = namedtuple('Parameter', 'value status error')
    safeStringTypes = [ParameterType.safeString, ParameterType.safeStringWithWhiteSpace]
    # Start with JSON, go to form data and then request query string
    try:
        requestData = request.json.get(field)
    except (JSONDecodeError, AttributeError, TypeError):
        requestData = None
    if requestData is None or requestData == '':
        requestData = request.forms.get(field)
    if (requestData is None or requestData == '') and allowGet is True:
        requestData = request.query.get(field)
        if requestData is None or requestData == '':
            requestData = None

    # If raw parameter is not found return.
    if requestData is None or requestData == '':
        return Parameter(None, missingParameterStatus, "parameter {} was not specified".format(field))

    # Strip leading and trailing whitespaces;
    if isinstance(requestData, str):
        requestData = requestData.strip()

    if param_type in safeStringTypes:
        max_val = 255 if max_val is None else max_val
        isValid = is_string_simple(requestData, whitespace=allowWhiteSpace, max_len=max_val, min_len=min_val)
        if not isValid:
            whiteSpaceMessage = "without spaces"
            if allowWhiteSpace:
                whiteSpaceMessage = "spaces allowed"
            return Parameter(None, 400, "parameter {} must be alpha numeric {} with length between {} and {}".
                             format(field, whiteSpaceMessage, min_val, max_val))
    elif param_type == ParameterType.string:
        max_val = 255 if max_val is None else max_val
        isValid = (max_val >= len(requestData) >= min_val)
        if not isValid:
            return Parameter(None, 400,
                             "parameter {} must have length between {} and {}".format(field, min_val, max_val))
    elif param_type == ParameterType.list:
        requestData = requestData.split(',')
    elif param_type == ParameterType.ip:
        if not is_valid_ip(requestData):
            if not is_valid_ip6(requestData):
                return Parameter(None, 400, "parameter {} is not a valid IP address".format(field))
    elif param_type == ParameterType.path:
        if not os.path.exists(requestData):
            return Parameter(None, 400, "parameter {} is not a valid path address".format(field))
    elif param_type == ParameterType.percent:
        requestData = _p2f(requestData)
        if requestData is None:
            return Parameter(None, 400, "parameter {} is not a valid percentage number".format(field))
    elif param_type == ParameterType.debugLevel:
        requestData = eval(requestData) if requestData in ['DEBUG', 'WARN', 'INFO', 'ERROR'] else None
        if requestData is None:
            return Parameter(None, 400, "parameter {} is not a valid debug level".format(field))
    elif param_type == ParameterType.objectId:
        isValid = ObjectId.is_valid(requestData)
        if not isValid:
            return Parameter(None, 400, "parameter {} is an invalid objectId".format(field))
    elif param_type == ParameterType.int:
        isNumber = True
        try:
            requestData = int(requestData)
        except ValueError:
            isNumber = False
        max_val = sys.maxint if max_val is None else max_val
        isValid = isNumber and (max_val >= requestData >= min_val)
        if not isValid:
            return Parameter(None, 400,
                             "parameter {} must be an integer between {} and {}".format(field, min_val, max_val))
    elif param_type == ParameterType.float:
        isNumber = True
        try:
            requestData = float(requestData)
        except ValueError:
            isNumber = False
        max_val = sys.maxint if max_val is None else max_val
        isValid = isNumber and (max_val >= requestData >= min_val)
        if not isValid:
            return Parameter(None, 400,
                             "parameter {} must be an number between {} and {}".format(field, min_val, max_val))
    elif param_type == ParameterType.bool:
        isBool = True
        try:
            if type(True) == type(requestData):
                pass
            elif str(requestData).lower() in ['true', '1']:
                requestData = True
            elif str(requestData).lower() in ['false', '0']:
                requestData = False
            else:
                isBool = False
        except ValueError:
            isBool = False
        isValid = isBool
        if not isValid:
            return Parameter(None, 400, "parameter {} must be a Boolean 'true' or 'false'")
    elif param_type == ParameterType.posixtime:
        isDate = True
        try:
            requestData = datetime.utcfromtimestamp(float(requestData))
        except ValueError:
            isDate = False
        max_val = sys.maxint if max_val is None else max_val
        isValid = isDate and (max_val >= requestData >= min_val)
        if not isValid:
            now = datetime.now()
            unix = time.mktime(now.timetuple())
            min_val_unix = time.mktime(min_val.timetuple())
            max_val_unix = time.mktime(max_val.timetuple())
            return Parameter(None, 400, 'parameter {} must be a date between {} ({}) and {} ({}) in POSIX time format. '
                                        'Current time is {} ({})'.format(field, min_val.strftime("%x %X"), min_val_unix,
                                                                         max_val.strftime("%x %X"), max_val_unix,
                                                                         now.strftime("%x %X"), unix))
    else:
        return Parameter(None, status=400, error="parameter {} not valid".format(field))

    # No errors
    retVal = Parameter(value=requestData, status=200, error=None)

    return retVal


def ip_to_int(addr):
    # converts an ip address string e.g. "192.168.2.2" to an integer
    if addr is None:
        return 0
    fields = addr.split('/')
    if 2 >= len(fields) > 0:
        try:
            rv = struct.unpack("!I", socket.inet_aton(addr))[0]
        except socket.error:
            rv = 0
    else:
        rv = 0
    return rv


def ip6_to_int(ipv6_addr):
    return int(hexlify(socket.inet_pton(socket.AF_INET6, ipv6_addr)), 16)


def convert_cidr_val(cidr, max_val):
    val = 0
    for x in range(max_val):
        val <<= 1
        if int(x) < int(cidr):
            val += 1
    return val


def get_network_ip(ip, netmask):
    """
    Gets the network IP of a network given a node IP
    Args:
        ip: String representation of a node IP. E.G. "192.168.1.2"
        netmask: String representation of the netmask. E.G. "255.255.255.0"
    Returns: String - network address
    """
    ipOctets = ip.split(".")
    netMaskOctets = netmask.split(".")
    netIP = ""
    for i, o in enumerate(ipOctets):
        netOct = int(o) & int(netMaskOctets[i])
        netIP += str(netOct)
        if i < 3:
          netIP += "."
    return netIP


def cidr_to_netmask(cidr):
    try:
        mask = int(cidr)
    except ValueError:
        return None
    if mask < 0 or mask > 32:
        return None
    bits = 0
    for i in xrange(32-mask, 32):
        bits |= (1 << i)
    return socket.inet_ntoa(struct.pack('>I', bits))

def netmask_to_cidr(netmask):
    """Returns cidr suffix when given netmask"""
    return IPv4Network((0,netmask)).prefixlen

def break_ip_addr(ip_addr):
    data = ip_addr.split('/')
    if 2 >= len(data) > 1:
        addr = data[0]
        try:
            cidr = int(data[1])
        except ValueError:
            cidr = -1
    else:
        addr = ip_addr
        cidr = -1
    if is_valid_ip6(addr):
        af_type = socket.AF_INET6
        cidr = cidr if cidr > 0 else 128
    elif is_valid_ip(addr):
        af_type = socket.AF_INET
        cidr = cidr if cidr > 0 else 32
    else:
        return None, 0, 0
    return af_type, addr, cidr


def addr_to_int(ip_addr):
    """
    parses the IP address checks if it's valid and set up the min and max values for the
    range for integer comparisons
    :param ip_addr:
    :return:
    """
    data = ip_addr.split('/')
    if 2 >= len(data) > 1:
        addr = data[0]
        cidr = data[1]
    else:
        addr = ip_addr
        cidr = -1
    if is_valid_ip6(addr):
        af_type = socket.AF_INET6
        value = ip6_to_int(addr)
        cidr = cidr if cidr > 0 else 128
        mask = convert_cidr_val(cidr, 128)
        range_val = ~mask & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    elif is_valid_ip(addr):
        af_type = socket.AF_INET
        value = ip_to_int(addr)
        cidr = cidr if cidr > 0 else 32
        mask = convert_cidr_val(cidr, 32)
        range_val = ~mask & 0xFFFFFFFF
    else:
        return None, 0, 0

    min_val = value & mask
    max_val = min_val + range_val
    return af_type, min_val, max_val


def is_valid_port(p):
    rv = False
    try:
        port = int(p)
        if 0 <= port <= 65535:
            rv = True
    except ValueError:
        rv = False
    return rv


def is_valid_vtag(p):
    rv = False
    try:
        port = int(p)
        if 0 < port < 4096:
            rv = True
    except ValueError:
        rv = False
    return rv


def is_valid_netmask(nm):
    if is_valid_ip(nm):
        nm = struct.unpack('!I', socket.inet_pton(socket.AF_INET, nm))[0]

        # to find valid netmask:
        # a netmask must be a series of 1 bits followed by a series of 0 bits. 0's cannot be intermixed with 1's.
        # i.e. 1111 1111 1111 1111 1111 1111 1111 0000
        # and not: 1111 1111 1110 1111 1011 1100 0000 0000
        #
        # 1. To determine this is the case, first we make sure the address isn't just 0.
        # 2. Next, take the inverse of the address' bits, called x
        #       (compensate for python's interpretation of inverse/2's complement)
        #       x = ~(1111 1111 1111 0000) = 0000 0000 0000 1111
        # 3. Add 1 to this, called y
        #       y = x + 1 = 0000 0000 0001 0000
        # 4. Compute x & y. If 0, netmask is valid.
        #       x & y = 0000 0000 0000 1111 & 0000 0000 0001 0000 = 0, valid
        if nm == 0:
            return False

        x = ~nm & 0xFFFF
        y = (x + 1) & 0xFFFF

        if x & y == 0:
            return True
    return False


def int_to_ip4(ip):
    if ip < 0:
        packed_ip = struct.pack('!L', ip % 2 ** 32)
    else:
        packed_ip = struct.pack('!L', ip)
    return socket.inet_ntoa(packed_ip)


def is_valid_hostname(hname):
    if len(hname) > 255:
        return False
    if hname[-1] == ".":
        hname = hname[:-1]
    ok = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(ok.match(x) for x in hname.split("."))


def is_valid_ip(addr):
    rv = False
    if addr is None:
        return False
    fields = addr.split('/')
    if 2 >= len(fields) > 0:
        try:
            socket.inet_pton(socket.AF_INET, fields[0])
            rv = True
        except socket.error:
            rv = False
        if len(fields) == 2:
            try:
                mask = int(fields[1])
                if not (32 >= mask >= 0):
                    rv = False
            except ValueError:
                rv = False
    else:
        rv = False
    return rv


def is_valid_ip6(addr):
    if addr is None:
        return False
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except socket.error:
        return False


def is_valid_eth(addr):
    fields = addr.split(':')
    if len(fields) != 6:
        return False
    for f in fields:
        if len(f) != 2:
            return False
        try:
            octet = int(f, 16)
            if octet < 0 or octet > 256:
                return -3
        except ValueError:
            return False
    return True


def reset_counters():
    system_settings = my_db().system_settings.find_one()
    if system_settings:
        if get_capture_mode() == 'myricom':
            clean_counters_cmd = "/opt/snf/bin/myri_counters -c"
            p = gevent.subprocess.Popen(clean_counters_cmd, stdout=gevent.subprocess.PIPE, shell=True)
            p.communicate()


def hostname_ip():
    """
    For 1804 the output of ifconfig is: inet addr:10.51.10.160  Bcast:10.51.10.255  Mask:255.255.255.0
    :return: ip address
    """
    hostname_cmd = "hostname -I"
    p = subprocess.Popen(hostname_cmd, stdout=gevent.subprocess.PIPE, shell=True)
    sout, serr = p.communicate()
    ips = sout.split()
    capture_ips = [x[0].split('/')[0] for x in Consts.TRAFFIC_ADDRESSES.values()]
    for ip in ips:
        if ip not in capture_ips:
            return ip
    return "not_set"


def mkdir_on_all_drives(username, path):
    """
    Creates the directory path on all drives, supports username/jobId/groupId/recordingId
    :return:
    """
    rv = {'status': 'success'}
    drives = my_db().drives.find({'enabled': True})
    for a_drive in drives:
        if a_drive.get('enabled'):
            drive_path = a_drive.get('path')
            full_path = os.path.join(drive_path, path)
            try:
                os.makedirs(full_path, 700)
            except OSError as exc:
                if exc.errno == errno.EEXIST and os.path.isdir(full_path):
                    pass
                if exc.errno == errno.ENOSPC:
                    my_logger.error("mkdir couldn't open a directory because the disk is full")
                    rv = {'status': 'error: disk is full'}
                else:
                    my_logger.error("mkdir couldn't open a directory because of an error {}".format(exc))
                    rv = {'status': 'error: disk error'}
    return rv


def update_recording_info(f_info):
    """
    When deleting a file from the database we want to update the recording info
    :param f_info:
    :return: True if successfully updated - False if the recording isn't in the database
    """
    rv = True
    ids = extract_ids_from_path(f_info.get("path"))
    try:
        recording_id = ids['recording_id']
        wr = my_db().recordings.update({"_id": ObjectId(recording_id)},
                                       {"$inc": {"filesInfo.totalSize": -f_info.get("size", 0),
                                                 "filesInfo.fileCount": -1}})
        if not wr['updatedExisting']:
            rv = False
            # my_logger.warn("Trying to update a recording that isn't in the database {}".format(recording_id))
    except TypeError:
        my_logger.error('extract_ids_from_path: failed to extract recording id from:{}'.format(f_info.get("path")))
    return rv


def delete_from_a_drive(in_path):
    """
    Deletes files from a single drive/path
    :param in_path:
    :return:
    """
    rv = {'status': 'success'}
    start_time = time.time()
    # cursor = my_files_db().files.find({"path": {"$regex": ".*{}.*".format(in_path)}})
    ids = extract_ids_from_path(in_path)
    try:
        recording_id = ids['recording_id']
        f_collection = my_files_db()[recording_id]
        cursor = f_collection.find({})

        if cursor is not None:
            for c in cursor:
                # we only update the database here - the rm -rf of a directory is much more efficient
                update_recording_info(c)
        # now remove the directory
        try:
            rm_cmd = "nice -20 rm -rf {}".format(in_path)
            p = gevent.subprocess.Popen(rm_cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, shell=True)
            sout, serr = p.communicate()
            rc = p.returncode
            if rc != 0 or serr != '':
                my_logger.warn("rm command: {} returned with RC={} stderr: {}".format(rm_cmd, rc, serr))
        except OSError:
            my_logger.warn("Error while removing: {}".format(in_path))
            rv = {'status': 'error'}
        my_logger.debug("It took {} seconds to to delete: {} files from path: {}".
                        format(time.time() - start_time, cursor.count(), in_path))
    except TypeError:
        my_logger.error('delete_from_a_drive: failed to extract recording id from:{}'.format(in_path))

    return rv


def delete_from_all_drives(in_path):
    """
    Cleans a job, group or a recording from all drives

    :param in_path: the path inside the drive
    :return:
    """
    rv = {'status': 'success'}
    my_logger.debug("Removing from all drives: {}".format(in_path))
    db = my_db()
    drives = db.drives.find({'enabled': True}) if db is not None else []
    for a_drive in drives:
        if "DATA_" in a_drive['name']:
            bur_db.drives.update(
                {'name': a_drive['name']},
                {"$set": {'cleaning': True}})
            delete_from_a_drive(os.path.join(a_drive['path'], in_path))
            bur_db.drives.update(
                {'name': a_drive['name']},
                {"$set": {'cleaning': False}})
    return rv


def user_in_system(username):
    try:
        uid = pwd.getpwnam(username)[2]
        return True
    except KeyError:
        return False


def start_mongod():
    """
    A utility method to start mongod - in case we have a connection failure
    :return:
    """
    if process_is_running("mongod"):
        return 0
    if baseimage() == 1804:
        start_cmd = "systemctl start mongodb.service"
    else:
        my_logger.debug("Base image is: {} - cant check mongo".format(baseimage()))
        return 1

    p = gevent.subprocess.Popen(start_cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=True)
    sout, serr = p.communicate()
    rc = p.returncode
    if my_logger is not None:
        my_logger.debug("Start mongod output: {}".format(sout))
    if rc != 0 or serr != '' and my_logger is not None:
        my_logger.warn("Start mongod error: RC={} stderr: {}".format(rc, serr))
    return rc


def stop_mongod():
    """
    A utility method to start mongod - in case we have a connection failure
    :return:
    """
    if not process_is_running("mongod"):
        return 0
    start_cmd = "mongod --sysState"
    p = gevent.subprocess.Popen(start_cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=True)
    sout, serr = p.communicate()
    rc = p.returncode
    if my_logger is not None:
        my_logger.debug("Stop mongod output: {}".format(sout))
    if rc != 0 or serr != '' and my_logger is not None:
        my_logger.warn("Stop mongod error: RC={} stderr: {}".format(rc, serr))
    return rc


def debug_level(val):
    try:
        dl = int(val)
    except (ValueError, TypeError):
        dl = DEBUG
    if dl not in [DEBUG, WARN, ERROR, INFO]:
        dl = DEBUG
        print("Error: debug level: {} isn't a valid level, default to: {}".format(dl, DEBUG))
        traceback.print_stack()
    return dl


def cvu_port_convert(p):
    """
    make sure we have ports formatted correctly support both X and X.Y formates

    :param p:
    :return:
    """
    port = 0
    sport = str(p)
    parts = sport.split('.')
    try:
        if len(parts) > 1:
            port = (int(parts[0]) - 1) * 4 + int(parts[1])
        else:
            port = int(parts[0])
    except ValueError:
        pass
    return port


def run_disk_df(path, label=None):
    """
    Returns the availability of the disk in bytes, divide by 1e9 if you want to work in GB
    :type path: dict
    :return: the availability in bytes if the disk is mounted, and None if the disk isn't mounted
    """
    rv = {}
    if path is None:
        my_logger.warn("path is none at run_disk_df")
        return rv
    df_cmd = "df {}".format(path)
    p = gevent.subprocess.Popen(df_cmd, stdout=gevent.subprocess.PIPE, shell=True)
    sout, serr = p.communicate()
    if p.returncode != 0:
        my_logger.error("Failed to run df command: {} {}".format(sout, serr))
        return rv
    lines = sout.splitlines()
    if len(lines) == 0:
        my_logger.error("df command: '{}' returned nothing".format(path, df_cmd))
        return rv
    l = lines[1]
    s = l.split()
    if label and label not in s[5]:
        my_logger.error("{} is not mounted (df command: '{}' returned:'{}')".format(path, df_cmd, l))
        return rv
    # ind = s[5].split('/')[2]
    kblocks = float(s[1])
    usage = float(s[4].strip('%')) / 100
    used = float(s[2]) * 1024

    # note: the availability columns is misleading in df (see:
    #   http://unix.stackexchange.com/questions/197778/ext4-disk-space-not-reclaimed-after-deleting-files)
    # avail = total - used
    # but we're trying to be more conservative now

    # avail = float(s[3]) * 1024 + empty_size + tmp_file_size  # when drives are empty df shows 18MB of overhead # / 1e9
    avail = float(s[3]) * 1024  # when drives are empty df shows 18MB of overhead # / 1e9
    # now run df -i to find the number of files (inodes) on the drive
    df_cmd = "df -i {}".format(path)
    p = gevent.subprocess.Popen(df_cmd, stdout=gevent.subprocess.PIPE, shell=True)
    sout, serr = p.communicate()
    if p.returncode != 0:
        my_logger.error("Failed to run df -i command: {} {}".format(sout, serr))
    lines = sout.splitlines()
    l = lines[1]
    s = l.split()
    nodes = int(float(s[2]))
    try:
        avg_size = used / nodes
    except ZeroDivisionError:
        avg_size = 0

    rv = {
        'kblocks': kblocks,
        'util': usage,
        'avail': avail,
        'used': used,
        'df_usage': usage,
        'files': nodes,
        'avg_size': avg_size
    }
    return rv


class myIpc(object):
    def __init__(self, logger, channel, message_callback_function=None):
        self.logger = logger
        self.ipc = None
        self.defaultChannel = channel
        self.caller = inspect.stack()[1][3]

        # only allow None or a callable function to be assigned.
        if message_callback_function is not None and not callable(message_callback_function):
            raise ValueError("message_handler argument must be a function")

        self.message_callback_function = message_callback_function

        if message_callback_function is not None:
            gevent.spawn(self.readMessages)

        gevent.spawn(self.keepAiveLoop)

    def keepAiveLoop(self):
        while True:
            #tried setsockopt socket.TCP_KEEP*
            self.send_msg({}, 'keepalive')
            gevent.sleep(3)

    def ensure_ipc(self):
        if self.ipc is None:
            self.logger.debug("Connecting to IPC channel")
            self.ipc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                self.ipc.connect("/tmp/pcapIPC")
                return True
            except socket.error as e:
                self.logger.warn("The pcapIPC isn't available ({}: {})".format(e.errno, e.strerror))
                # control_process('rt', 'start')
                self.ipc = None
                return False
        return True

    def send_msg(self, data, channel=None):
        channelToUse = channel if channel is not None else self.defaultChannel
        msg_dict = {
            "channel": channelToUse,
            "message": data
        }
        self.send_msg_verbatim(msg_dict)

    def send_msg_verbatim(self, msg_dict):
        msg = json.dumps(msg_dict , separators=(',', ':'))

        # self.ipc.send_msg(json.dumps(msg, separators=(',', ':')))
        if not self.ensure_ipc():
            return

        try:
            self.ipc.send(msg)
            self.ipc.send('\n')
        except socket.error as e:
            self.logger.debug("Socket error({0}): {1}".format(e.errno, e.strerror))
            # The pcapIPC isn't available (104: Connection reset by peer)
            # Socket error(32): Broken pipe
            try:
                gevent.sleep(1)
                self.ipc = None
                if not self.ensure_ipc():
                    return

                self.ipc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.ipc.connect("/tmp/pcapIPC")
                sent = self.ipc.send(msg+'\n')
                if sent == 0:
                    self.logger.debug("Unable to send. resetting&reconnecting.")
                    self._removePcapIpcSocket()
                self.logger.debug("Reconnected to the IPC channel")
            except socket.error as e:
                self.logger.warn("The pcapIPC isn't available ({}: {})".format(e.errno, e.strerror))
                self.ipc = None

    def _removePcapIpcSocket(self):
        try:
            self.ipc.close()
        except:
            pass
        self.ipc = None

    def readMessages(self):
        while True:
            try:
                if not self.ensure_ipc():
                    raise Exception('Could not connect')

                # subscribeOpts = {
                #     'type':'dataChange',
                #     'dataNotifyChannels': ['dbUpdate', 'dbDelete'],
                #     'dataNotifyCollections': ['recording', 'portgroup', 'endpointgroup', 'mfdmonitor', 'mfdfeedgroup',
                #                               'staticroute', 'perfMonitors', 'baselines']
                # }
                # subScribeOpts = {'channel':'command', 'name':'subscribe', 'opts': subscribeOpts}
                # subscribeMessage = json.dumps(subScribeOpts, separators=(',', ':'))
                # self.ipc.send(subscribeMessage+'\n')

                file = self.ipc.makefile('r', 0)


                for l in file:
                    if l == '':
                        self.logger.info(" receive notification ended")
                        break
                    data = l.strip('\n')
                    idata = json.loads(data)
                    # self.logger.info("received message in (%s)" %(self.uxdomainFileName))
                    # self.logger.info('data received {0} {1}'.format(type(idata), idata))
                    try:
                        if self.message_callback_function is not None:
                            self.message_callback_function(idata)
                    except:
                        self.logger.error("Exception while invoking message_callback_function {0}".format( sys.exc_info()))

                try:
                    file.close()
                except:
                    pass

                gevent.sleep(3)

            except Exception as ex:
                self.logger.error("error reading messages {0}".format(ex))
                gevent.sleep(3)

class myLs(object):
    def __init__(self, logger):
        self.logger = logger
        self.p = None
        self.c = 0

    def run_myls(self, path):
        my_env = os.environ.copy()
        my_env["PATH"] += "/home/cpacket/packages/cstordep/bin:/home/cpacket/sandbox/src/cstor_gulp"
        _cmd = 'myls -p {} -s pcap'.format(path)
        # self.logger.debug("running: {}".format(_cmd))
        self.p = subprocess.Popen(_cmd, bufsize=-1, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  shell=True, env=my_env)
        if self.p.poll() is not None:
            rc = self.p.returncode
            if rc != 0:
                e = self.p.stderr.read()
                if rc == 127:
                    self.logger.warn("Failed to run myls on: {}".format(path))
                else:
                    serr = self.p.stderr.readline( )        # read the file header and ignore
                    self.logger.error("Open offline files RC={} stderr: {}".format(rc, serr))
                return False

        return True

    def __iter__(self):
        return self

    def close(self):
        try:
            if self.p is not None:
                self.p.terminate()
        except OSError:
            # process already terminated - we'll get a a no such process error
            pass

    def next(self):
        while True:
            h = self.p.stdout.readline()
            if h == '':
                m = self.p.poll()
                if m is not None:
                    e = self.p.stderr.read()
                    # self.logger.debug("myls parsing complete, read: {}: rc={} stderr: ({})".format(self.c, m, e))
                    break
                else:
                    continue
            # print self.c, h
            self.c += 1
            return h
        self.close()
        raise StopIteration()


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


def read_str_from_file(f_name):
    try:
        with open(f_name, 'r') as f:
            s = f.read().strip()
    except:
        s = None
    return s


def read_int_from_file(f_name):
    val = 0
    try:
        with open(f_name, 'r') as f:
            s = f.read().strip()
            val = int(s)
    except:
        val = -1
    return val


def my_db():
    global bur_db
    if bur_db is None:
        try:
            client = MongoClient('127.0.0.1', 27017)
            bur_db = client.burnside_db
        except py_errors.ConnectionFailure:
            print("Helper functions cannot connect to database")
    return bur_db


def my_files_db():
    global files_db
    if files_db is None:
        try:
            client = MongoClient('127.0.0.1', 27017)
            files_db = client.files_db
        except py_errors.ConnectionFailure:
            print("Helper functions cannot connect to database")
    return files_db


def read_base_image_file():
    global base_image
    if base_image is None:
        base_image = 1804
        try:
            # print("reading base image file at: {}".format(Consts.BASEIMAGE_FILE))
            with open(Consts.BASEIMAGE_FILE, 'r') as base_image_fd:
                lines = base_image_fd.readlines()
                for line in lines:
                    if '1804' in line:
                        base_image = 1804
                        break
                    else:
                        print("WARNING: Base-image file has value {}. But assuming it's 1804".format(line))
                        break
        except IOError:
            print("WARNING: Base-image file is missing assuming it's 1804")
        # print("INFO the base image version: {}".format(base_image))
    return base_image


def baseimage():
    return read_base_image_file()


def get_oldest_time(recording_id=None):
    """
    Finds the oldest file in the files database for a specific recording
    :return:
    """
    tm = time.time()
    recordings = []
    if recording_id is None:
        c_names = my_files_db().collection_names(include_system_collections=False)
        for c in c_names:
            recordings.append(c)
    else:
        recordings.append(str(recording_id))
    for r in recordings:
        f_collection = my_files_db()[r]
        cursor = f_collection.find({}).sort("time", pymongo.ASCENDING).limit(1)
        try:
            tm = min(cursor[0].get("time"), tm)
        except (TypeError, IndexError):
            # my_logger.warn("Didn't find any file for this recording")
            pass
    return tm


def get_newest_time(recording_id=None):
    """
    Finds the newest file in the files database based on the recording ID
    Since it might take a few seconds to finish writing the files to disks and we have multiple concurrent threads
    writing at the same time, we might be missing files within the last 20-30 seconds. So we return as the newest file
    on the disk the time where we feel comfortable that we don't have any gaps
    :return:
    """
    recordings = []
    time_range_limit = 30
    tm = 0
    if recording_id is None:
        c_names = my_files_db().collection_names(include_system_collections=False)
        for c in c_names:
            recordings.append(c)
    else:
        recordings.append(str(recording_id))
    for r in recordings:
        f_collection = my_files_db()[r]
        cursor = f_collection.find({}).sort("time", pymongo.DESCENDING).limit(time_range_limit)
        try:
            tm = max(cursor[0].get("time"), tm)
        except (TypeError, IndexError):
            # my_logger.warn("Didn't find any file for this recording")
            pass
    return tm


def clean_sys_data():
    """
    Cleans the SYS DATA folder
    :return:
    """
    cmd = "rm /media/SYS_DATA/time_*"
    my_logger.debug("Cleaning old files in tmp directory: {}".format(cmd))
    p = gevent.subprocess.Popen(cmd, stdout=gevent.subprocess.PIPE, stderr=gevent.subprocess.PIPE, shell=True)
    sout, serr = p.communicate()
    my_logger.debug("stdout: {}; stderr: {}".format(sout, serr))


def init_db_and_logger(my_name):
    global my_logger
    sys_settings = None
    if my_db() is not None:
        try:
            sys_settings = my_db().system_settings.find_one()
        except py_errors.ConnectionFailure as e:
            print("Helper Functions failed to connect to mongodb: {}".format(e.message))
            sys_settings = None

    if sys_settings is not None:
        dl = debug_level(sys_settings.get('debug_level'))
        console = sys_settings.get('consolelog', Consts.DEFAULT_SETTINGS['consolelog'])
        udp_dest = sys_settings.get('udp_dest', Consts.DEFAULT_SETTINGS['udp_dest'])
        udp_port = sys_settings.get('udp_port', Consts.DEFAULT_SETTINGS['udp_port'])
        my_logger = MyLogging.MyLogger(my_name, logfile=None, console=console,
                                       level=dl, udp_dest=udp_dest, udp_port=udp_port)
    else:
        my_logger = MyLogging.MyLogger(my_name, console=Consts.DEFAULT_SETTINGS['consolelog'])
        print("Didn't connect to database to retrieve settings - ignore if this is for docstring creation")


def is_valid_sed(drive_path):
    """
    Checks if the drive is an SED or not

    :param drive_path: The drive path that needs to be checked
    :return: True / False
    """
    if not drive_path:
        return False
    _cmd = "/sbin/hdparm -I {}".format(drive_path)
    p = gevent.subprocess.Popen(_cmd, stdout=gevent.subprocess.PIPE, shell=True)
    sout, serr = p.communicate()
    if p.returncode != 0 or not sout:
        return False

    for entry in Consts.SED_MODELS:
        if entry in sout:
            return True

    return False


if __name__ == "__main__":
    sys.exit("not supposed to run as a main module")
else:
    init_db_and_logger(__name__)
