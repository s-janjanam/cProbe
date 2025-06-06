from gevent import monkey
monkey.patch_all()

import copy
import sys
sys.path = ['.'] + sys.path
from ssh_config import SshConfig
from acl_config import ACLConfig
from snmp_config import SnmpConfig, ProcessHandler
from store.db_store import SystemSettingsStore, AclConfigurationStore
from store.user import UserStore
from local_user_service import LocalUserService, UserManagementError, verify_store

import os
import sys
import bottle
from bottle import Bottle, run, response, request
from logging import DEBUG
from HelperFunctions import MyJsonEncoder, extract_parameter, ParameterType, start_mongod, \
    debug_level, control_process, hostname_ip, process_is_running, \
    myIpc, reset_counters, baseimage, \
    detect_virtual, is_valid_ip, init_dpdk_nics, run_cmd, tar_files
from bson.objectid import ObjectId
import time
from datetime import timedelta
import json
import inspect
import socket
from consts import Consts, SECURE_ERASE_LOG, LOG_LINES_LIMIT, ACL_WHITELIST, ACL_CLUSTER
import pymongo
from pymongo import MongoClient, errors
from ipaddress import ip_network
import MyLogging
import settings
from simplejson import JSONDecodeError
from MyAppconfig import Myappconfig
from collections import OrderedDict
import gevent
from cleanupTask import driveWrapper, resync_db_to_disks, delete_user_files
import traceback
from IpFixParser import cIpFixSettings
from DbData import DbCollection
from updatemgr import UpdateMgr
import PtpCfg
from ExternalAuthController import ExternalAuthController, encode_secrets
from StaticRouteManagement import StaticRouteManager
from BottleHelper import cp_auth
from optparse import OptionParser
from gevent import Greenlet, subprocess, queue
from gevent.lock import BoundedSemaphore
from cprobe_control import cProbeControl
from snmp_util import *
from snmp_constants import *
from cpConfig.ub18cfg import Ub18Cfg as ubConfig

system_lock = BoundedSemaphore()
diag_log_lock = BoundedSemaphore()


class CstorAdminApi(object):
    """
    API implementation for the administrative functionality of cstor
    """

    def __init__(self, bottleapp, mongo_client, user_management, ssh_config, acl_config, logger, disk_erase_logger):
        self.bottleapp = bottleapp
        self.logger = logger
        self.erase_logger = disk_erase_logger
        self.mongo_client = mongo_client
        self.burnside_db = mongo_client.burnside_db
        self.files_db = mongo_client.files_db
        self.db_handles = {}
        self.infoIpc = myIpc(logger, "adminInfo")
        self.urgentIpc = myIpc(logger, "adminUrgent")
        self.warningIpc = myIpc(logger, "adminWarning")
        self.progress_ipc = myIpc(logger, "progressUpdate")
        self._user_management = user_management
        self._restoring = False
        if getattr(sys, 'frozen', False):
            self.app_path = os.path.dirname(sys.executable)
            self.main_dir = os.path.abspath(os.path.join(self.app_path, ".."))
            self.html_root = os.path.join(self.main_dir, 'html')
        elif __file__:
            self.app_path = os.path.dirname(__file__)
            self.main_dir = os.path.abspath(os.path.join(self.app_path, ".."))
            self.html_root = os.path.join(self.main_dir, 'html')
        self.static_route_manager = StaticRouteManager(self.burnside_db.static_route_settings, self.logger)
        self.my_public_methods = []
        self.traps_list = []
        self.snmp_dict = {}
        self._register_routes()
        self.update_mgr = UpdateMgr(logger=self.logger)
        self.ssh_config = ssh_config
        self.acl_config = acl_config
        self.snmp_v2c_config = SnmpConfig(mongo_client, logger=self.logger, version=SNMP_VERSION_V2C)
        self.snmp_v3_config = SnmpConfig(mongo_client, logger=self.logger, version=SNMP_VERSION_V3)
        self.ubCfg = ubConfig()
        self._init_default_snmp()
        self._init_acl_configuration()
        if self.burnside_db.system_settings.find_one({}).get('run_background_task', True):
            control_process('background', 'start')
        wr = self.burnside_db.system_settings.update_one(
            {},
            {"$set": {'system_state': 'ok', 'log_collection': 'idle'}})
        self.acl_members_limit = self.burnside_db.system_settings.find_one({}).get('acl_members_limit', 200)
        try:
            self.acl_members_limit = int(self.acl_members_limit)
        except (TypeError, ValueError):
            self.logger.warn("Invalid value for acl_members_limit : {}. Defaulting to 200".format(self.acl_members_limit))
            self.acl_members_limit = 200
        self._ensure_file_db_index()
        self.engine_id = None
        self.urgentIpc.send_msg("System OK")

    def _register_routes(self):
        """
        Register all the public methods of the class as sys/api_ver/url
        :type self: src.cstor.src.admin_app.CstorAdminApi
        """
        methods = inspect.getmembers(self, lambda a: inspect.ismethod(a))
        for a_method in methods:
            if not (a_method[0].startswith('_')):
                self.logger.debug("Registering route: {}".format(a_method))
                self.my_public_methods.append(a_method)
        self.bottleapp.route("/sys/<api_ver:int>/<api_call>", method="POST", callback=self._handle_sys_call)
        self.bottleapp.route("/sys/<api_ver:int>/<api_call>", method="GET", callback=self._handle_sys_call)

    def _handle_sys_call(self, api_ver, api_call):
        for method in self.my_public_methods:
            if api_call == method[0]:
                if options.verbose:
                    self.logger.debug("sys call: {} version: {}".format(api_call, api_ver))
                if not "download" in api_call:
                    response.content_type = 'application/json; charset=UTF-8'
                    response.set_header("Cache-Control", "private, max-age=0, no-cache")
                return method[1]()
        self.logger.warn("unknown API SYS was called: {} version: {}".format(api_call, api_ver))
        bottle.abort(404, "{} is an unknown SYS call. Version: {}".format(api_call, api_ver))

    def _log_and_abort(self, err_code, err_msg, tb=False):
        """
        A utility function to log the error and abort the bottle operation
        :param err_code:
        :param err_msg:
        :return:
        """
        if tb:
            traceback.print_stack(limit=6)
        self.logger.warn(err_msg)
        # bottle.abort(err_code, err_msg)
        raise bottle.HTTPResponse(status=err_code, body=err_msg)

    def query(self):
        response.content_type = 'application/json'

        (q_db, status, error) = extract_parameter('db', param_type=ParameterType.string)
        if not q_db:
            raise bottle.HTTPResponse(status=status, body=error)

        (col, status, error) = extract_parameter('col', param_type=ParameterType.string)
        if not col:
            raise bottle.HTTPResponse(status=status, body=error)

        bdb = ['my_stats']
        cdb = ['lists', 'ports_map', 'settings', 'vlans_map', 'known_protocols']
        allowed = {'bdb': ('burnside_db', bdb), 'cnat': ('cnat_db', cdb)}

        # Read mongo find docs for query and fields options.   You can include or exclude fields but not both.   e.g.
        #   {"limit":100, "offset":1, "query": {"category": "gap", "epoc":{ "$gt": 1452898098}},
        #    "fields": {"category":0}}
        try:
            json_parms = request.json
        except ValueError:
            self.logger.warn('Unable to parse json parameters in query')
            return self._json_error("Unable to parse json parameters in query", 400,
                                    example='Expect json with optional specification of query,limit,offset,fields. '
                                           '{"query":{ ... } , "limit":100, "offset":0, fields={ ... }}')

        if q_db not in allowed.keys():
            self.logger.warn('db is not valid {}'.format(q_db))
            return self._json_error("db specified is not valid", 400)

        if col not in allowed[q_db][1]:
            msg = 'collection is not valid {} for {}'.format(col, q_db)
            self.logger.warn(msg)
            return self._json_error(msg, 400)

        database_name = allowed[q_db][0]

        handle = '{}.{}'.format(database_name,col)

        if handle not in self.db_handles.keys():
            collection = DbCollection(database_name, col)
            self.db_handles[handle] = collection
        else:
            collection = self.db_handles[handle]

        del json_parms['db']
        del json_parms['col']

        return collection.query(**json_parms)

    def _json_error(self, message, status=400, example=None):
        response.status = status
        response.content_type = 'application/json'
        output = {'message': message}
        if example:
            output['example'] = example
        return json.dumps(output)

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to stop the capturing process')
    def stopCapture(self):
        """
        .. http:post:: /sys/20141030/stopCapture

            Stops the capturing process on cstor

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
            :return:
        """
        self.logger.debug("stopping capture process")
        control_process('cstor_snf', 'stop')

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to start the capturing process')
    def startCapture(self):
        """
        .. http:post:: /sys/20141030/startCapture

            Starts the capturing process on cstor

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
            :return:
        """
        self.logger.debug("Starting capture process")
        control_process('cstor_snf', 'start')

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to stop the background process')
    def stopBackgroundTask(self):
        """
        .. http:post:: /sys/20141030/stopBackgroundTask

            Stops the background task

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
            :return:
        """
        self.logger.debug("stopping the background process")
        control_process('background', 'stop')
        self.burnside_db.system_settings.update(
            {},
            {"$set": {'run_background_task': False}},
            upsert=True)

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to start the background process')
    def startBackgroundTask(self):
        """
        .. http:post:: /sys/20141030/startBackgroundTask

            Starts the background process

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
            :return:
        """
        self.logger.debug("Starting the background process")
        control_process('background', 'start')
        self.burnside_db.system_settings.update(
            {},
            {"$set": {'run_background_task': True}},
            upsert=True)

    def _halt_cprobe_services(self):
        capture_mode = self.burnside_db.system_settings.find_one({}, {"_id": False, "capture_mode": True})
        if capture_mode and capture_mode.get('capture_mode') != 'cprobe':
            return
        for prc in Consts.CPROBE_PROCESSES:
            self.logger.debug("stopping process: {}".format(prc))
            control_process(prc, 'stop')

    def _halt_main_services(self, ignore_process_list=None):
        wr = self.burnside_db.system_settings.update(
            {},
            {"$set": {'system_state': 'halting'}})
        if baseimage() == 1804:
            process_to_skip = ['admin_app', 'mongodb', 'ssh', 'chrony', 'ptpd']
            process_to_skip.extend(ignore_process_list or [])
            for prc in Consts.SYSD_PROCESSES:
                if prc in process_to_skip or not process_is_running(prc):
                    continue
                self.logger.debug("stopping process: {}".format(prc))
                control_process(prc, 'stop')
        else:
            self.logger.warn("unsupported baseimage: {}".format(baseimage()))

    def _exit_process(self):
        wr = self.burnside_db.system_settings.update(
            {},
            {"$set": {'system_state': 'ok'}})

        sys.exit(-1)


    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to resynchronize the files database')
    def resyncFilesDB(self):
        """
        .. http:post:: /sys/20141030/resyncFilesDB

            Check the the files database is in sync with the drives and re-synchornizes if needed

            :param infoOnly: returns the information without re-sychnronizing

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """

        info_only = extract_parameter('infoOnly', ParameterType.bool).value
        info_only = True if info_only is None else info_only
        force = extract_parameter('force', ParameterType.bool).value
        force = True if force is None else force

        self._halt_main_services()
        rv = resync_db_to_disks(info_only=info_only, force=force)
        self._start_services()
        rsp = MyJsonEncoder().encode(rv)
        return rsp

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to clean all drives')
    def deleteAllDataFiles(self):
        """
        .. http:post:: /sys/20141030/deleteAllDataFiles
            This is just an interface function to support both the drive and disk nomenclature
        """
        return self.cleanAllDrives()

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to clean all drives')
    def cleanAllDisks(self):
        """
        .. http:post:: /sys/20141030/cleanAllDisks
            This is just an interface function to support both the drive and disk nomenclature
        """
        return self.cleanAllDrives()

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to clean all drives')
    def cleanAllDrives(self):
        """
        .. http:post:: /sys/20141030/cleanAllDrives

            Main interface for cleaning all the data

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        self.urgentIpc.send_msg("Cleaning all data from disks")
        body = queue.Queue()
        g = gevent.spawn(self._clean_all_drives, exit_process=True)
        gevent.sleep(0.0001)
        return body

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to secure erase all drives')
    def secureEraseDrives(self):
        """
        .. http:post:: /sys/20141030/secureEraseDrives

            Main interface for cleaning all the data

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        pattern = extract_parameter('pattern', ParameterType.string).value
        self.urgentIpc.send_msg("Secure erase all data from disks")
        self.logger.debug("Starting erase with pattern {}".format(pattern))
        _ = gevent.spawn(self._secure_erase_alldrives, exit_process=True, pattern=pattern)
        gevent.sleep(0.0001)

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to get partitions info')
    def getPartitionsInfo(self):
        """
        .. http:post:: /sys/20141030/getPartitionsInfo

            Main interface to get details of the partitions

            :statuscode 400: when form parameters are missing
            :statuscode 401: unauthorized to perform the action
            :return: status(error/success),message, currentPartition and passivePartition
        """
        ret_val = {
            'status': 'error',
            'message': '--',
            'currentPartition': '',
            'passivePartition': '',
            'passiveLabel': ''
        }
        response.status = 400
        self.logger.debug("Getting Partition info")

        # find out the current label
        my_cmd = "df -h /|tail -1"
        p = subprocess.Popen(my_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sout, serr = p.communicate()
        try:
            current_disk = sout.split()[0]
        except (TypeError, AttributeError, ValueError, KeyError):
            self.logger.error("Failed to find current partition with error {} ".format(serr))
            ret_val['message'] = 'Failed to find the current partition'
            return ret_val

        my_cmd = "lsblk -n -olabel {}".format(current_disk)
        p = subprocess.Popen(my_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sout, serr = p.communicate()
        if p.returncode == 0:
            current_label = sout.strip()
        else:
            self.logger.error("Failed to find current label with error {}".format(serr))
            ret_val['message'] = 'Failed to find the current label'
            return ret_val

        if current_label == 'sys1':
            passive_label = 'sys2'
        elif current_label == 'sys2':
            passive_label = 'sys1'
        else:
            self.logger.error("Invalid label type : {}".format(current_label))
            ret_val['message'] = 'Failed to find the passive label'
            return ret_val

        my_cmd = "lsblk -n -oname /dev/disk/by-label/{}".format(passive_label)
        p = subprocess.Popen(my_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sout, serr = p.communicate()
        if p.returncode == 0:
            passive_partition = "/dev/{}".format(sout.strip())
        else:
            self.logger.error("Passive partition not found: {} error: {}".format(sout, serr))
            ret_val['passiveLabel'] = passive_label
            ret_val['passivePartition'] = None  # to handle recover inactive partition call
            ret_val['message'] = 'Failed to find the passive partition'
            return ret_val

        ret_val['status'] = 'success'
        response.status = 200
        ret_val['currentPartition'] = current_disk
        ret_val['passivePartition'] = passive_partition
        ret_val['passiveLabel'] = passive_label
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to clear the passive partition')
    def secureErasePassivePartition(self):
        """
        .. http:post:: /sys/20141030/secureErasePassivePartition

            Main interface for cleaning the passive partition

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        partition_details = self.getPartitionsInfo()
        passive_partition = partition_details['passivePartition']
        passive_status = partition_details['status']
        passive_label = partition_details['passiveLabel']
        pattern = extract_parameter('pattern', ParameterType.string).value
        if passive_status == 'success':
            self.urgentIpc.send_msg("Secure erase of passive partition")
            _ = gevent.spawn(self._secure_erase_passive_partition, passive_partition=passive_partition,
                             partition_label=passive_label, pattern=pattern)
            gevent.sleep(0.0001)

    def _secure_erase_passive_partition(self, passive_partition, partition_label, pattern='dod'):
        """
        Main function to securely clean the passive partition
        Unmount the partition, clean, make file system and mount back the partition

        :param passive_partition: name of the passive partition
        partition_label: label of the passive partition
        pattern: pattern selected for the cleaning
        :return:
        """
        self.urgentIpc.send_msg("Started secure erase of passive partition")
        self.erase_logger.info("Started secure erase of {} with pattern {}".format(passive_partition, pattern))
        self.burnside_db.system_settings.update_one({}, {"$set": {'system_state': 'restarting'}})

        # unmounting the partition
        _cmd = "umount {}".format(passive_partition)
        p = subprocess.Popen(_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        sout, serr = p.communicate()
        if p.returncode == 0:
            self.logger.info("Unmounted {} partition for clearing".format(passive_partition))
        else:
            # the mount operation failed, keep the drive un-mounted
            self.logger.error("Umount command failed: {} error: {}".format(sout, serr))

        # scrubbing the partition
        self.logger.info("SCRUB the partition {}".format(passive_partition))
        self.urgentIpc.send_msg("Secure erase of {} in progress".format(passive_partition))
        self.erase_logger.info("Secure erase of partition - {} in progress".format(passive_partition))
        start = time.time()
        _cmd = "/usr/bin/scrub -b 512M -S -f -p {} {}".format(pattern, passive_partition)
        self.logger.info("SCRUB the partition : command {}".format(_cmd))
        p = subprocess.Popen(_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sout, serr = p.communicate()
        self.urgentIpc.send_msg("Secure erase in progress. Time elapsed(hh:mm:ss) {}".
                                format(timedelta(seconds=int(time.time() - start))))
        if p.returncode == 0:
            self.logger.info("Finished scrubbing the partition {}".format(partition_label))
        else:
            self.logger.error("Secure erase failure. command: ({}) {}".
                             format(_cmd, passive_partition))
        self.erase_logger.info("Secure erase of {} in progress. Time elapsed (hh:mm:ss) {}"
                               .format(passive_partition, timedelta(seconds=int(time.time() - start))))

        # creating file system for the partition
        _cmd = "mkfs.ext4 -L {0} /dev/disk/by-partlabel/{0}".format(partition_label)
        self.logger.info("Creating the file system: {} : command {}".format(partition_label, _cmd))
        p = subprocess.Popen(_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sout, serr = p.communicate()
        if p.returncode == 0:
            self.logger.info("Created the file system for {}".format(partition_label))
        else:
            self.logger.error("Error in creating file system for {}".format(partition_label))
        self.erase_logger.info("Waiting for the secure erase to be completed")

        # mkfs was not mounting back the drive after software update, manually mount back the partition
        _cmd = "mount {}".format(passive_partition)
        p = subprocess.Popen(_cmd, stdout=subprocess.PIPE, shell=True)
        sout, serr = p.communicate()
        if p.returncode == 0:
            self.logger.info("Mounted back {} the partition".format(passive_partition))
        elif p.returncode == 32:
            self.logger.info("Mounted already {} the partition".format(passive_partition))
        else:
            self.logger.error("Mount command failed: {} error: {}".format(sout, serr))

        self.urgentIpc.send_msg("Done secure erase of passive partition.")
        self.erase_logger.info("End of secure erase. Time Taken (hh:mm:ss) {}"
                               .format(timedelta(seconds=int(time.time() - start))))
        self.erase_logger.info("*" * 80)
        self.burnside_db.system_settings.update_one({}, {"$set": {'system_state': 'ok'}})
        self.urgentIpc.send_msg("System OK")

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to recover the passive partition')
    def recoverPassivePartition(self):
        """
         .. http:post:: /sys/20141030/recoverPassivePartition

            Main interface to get recover the passive partition if not available

            :statuscode 400: when form parameters are missing
            :statuscode 401: unauthorized to perform the action
            :return: status(error/success) and message
        """
        ret_val = {
            'status': 'error',
            'message': '--'
        }
        response.status = 400
        partition_details = self.getPartitionsInfo()
        passive_partition = partition_details['passivePartition']
        passive_label = partition_details['passiveLabel']
        passive_status = partition_details['status']
        if passive_status == 'success':
            self.logger.info("Passive partition already found {}".format(passive_partition))
            ret_val['message'] = 'Passive partition is already available'
            return ret_val
        elif passive_status == 'error' and passive_partition is None:
            # creating file system for the partition only if the partition is not available
            _cmd = "mkfs.ext4 -L {0} /dev/disk/by-partlabel/{0}".format(passive_label)
            self.logger.info("Creating the file system: {} : command {}".format(passive_label, _cmd))
            p = subprocess.Popen(_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sout, serr = p.communicate()
            if p.returncode == 0:
                self.logger.info("Created the file system for {}".format(passive_label))
            else:
                self.logger.error("Error in creating file system for {}".format(passive_label))
                ret_val['message'] = 'Failed to created the file system'
                return ret_val

            # mounting back the partition
            _cmd = "mount /media/{}".format(passive_label)
            self.logger.info("Mount back the partition {} : command {}".format(passive_label, _cmd))
            p = subprocess.Popen(_cmd, stdout=subprocess.PIPE, shell=True)
            sout, serr = p.communicate()
            if p.returncode == 0:
                self.logger.info("Mounted back {} the partition".format(passive_label))
            elif p.returncode == 32:
                self.logger.info("Mounted already {} the partition".format(passive_label))
            else:
                self.logger.error("Mount command failed: {} error: {}".format(sout, serr))
                ret_val['message'] = 'Failed to mount back the partition'
                return ret_val

        self.erase_logger.info("Recovered the passive partition")
        ret_val['status'] = 'success'
        ret_val['message'] = 'Recovered the passive partition'
        response.status = 200
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to reset counters')
    def resetCounters(self):
        """
        .. http:post:: /sys/20141030/resetCounters

            Main interface for cleaning all the data

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        return reset_counters()

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to drop databases')
    def dropDatabases(self):
        """
        .. http:post:: /sys/20141030/dropDatabases

           This action performs a factory settings resets

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        self.logger.debug("dropping databases")
        self._halt_main_services()
        self._clean_all_drives(control_services=False)
        # No need for self._drop_data_databases() here. clean_all_drives will take care of doing that
        self.mongo_client.drop_database('burnside_db')
        init_system_settings(self.burnside_db)  # initializes system settings
        _ = cIpFixSettings(self.logger)  # initializes cnat database
        # now quit and let systemd to restart the admin service
        self._exit_process()

    def _ensure_file_db_index(self):
        """
        Reattempt to create a time based indexing on the file_db database.
        """
        c_names = self.files_db.collection_names(include_system_collections=False)
        # Safe to attempt index creation (if already exists) as pymongo consider it as no-op
        for c in c_names:
            self.files_db[c].create_index([("time", pymongo.ASCENDING)])

    def _drop_data_databases(self):
        """
        cleans the databases related to indexing files and data on the disks
        """
        self.mongo_client.drop_database('ip_map_db')
        self.burnside_db.system_settings.update({}, {"$set": {'last_update_flow_time': 0}})
        self.mongo_client.drop_database('files_db')

    def _notify_cleanup_status(self, interval=5):
        """
        Utility function to send cleanup status
        """
        seconds = 0
        while True:
            gevent.sleep(interval)
            duration = str(timedelta(seconds=seconds))
            self.urgentIpc.send_msg(" Drive cleanup is in progress. Elapsed time :{} (approx)".format(duration))
            seconds += interval

    def _reset_files_and_recordings(self):
        """
        Drops files collection and Zeros out the recordings info
        """
        c_names = self.files_db.collection_names(include_system_collections=False)
        for c in c_names:
            self.files_db[c].drop()
        self._drop_data_databases()
        recordings = self.burnside_db.recordings.find({})
        for r in recordings:
            recording_id = str(r['_id'])
            f_collection = self.files_db[recording_id]
            f_collection.create_index([("time", pymongo.ASCENDING)])
            current_time = int(time.time())
            self.burnside_db.recordings.update({"_id": r["_id"]},
                                               {"$set": {"filesInfo.totalSize": 0,
                                                         "filesInfo.fileCount": 0,
                                                         "filesInfo.lastSpeed": 0,
                                                         "filesInfo.startTime": current_time,
                                                         "filesInfo.endTime": current_time,
                                                         "recordingStartTime": current_time,
                                                         "startTime": current_time}})

    def _clean_all_drives(self, exit_process=False, control_services=True):
        """
        Main function to clean all data from cStor. It reformats all the drives, drops the files collection and
        zeroes out the recordings info

        :param exit_process: Indicates if you need to exit the parent process or not
        :param control_services: Indicates if you need to stop/start the processes or not
        :return:
        """
        self.urgentIpc.send_msg("Cleaning all drives")
        if control_services:
            self._halt_main_services()

        self._reset_files_and_recordings()

        drives = self.burnside_db.drives.find({'mounted': True})
        num_data_drives = drives.count() - 1  # ignore system disk
        self.erase_logger.info("Start of Clean All Data of Data drives")
        self.erase_logger.info("Number of drives to be cleaned : {}".format(num_data_drives))
        i = 1
        jobs = []
        start = time.time()
        for a_drive in drives:
            if "DATA_" in a_drive['name']:
                if "SYS_DATA" in a_drive['name']:
                    continue
                # the drive is a data drive
                dw = driveWrapper(self.logger, self.burnside_db, a_drive['dev_path'])
                self.logger.debug("Reformatting drive: {}".format(a_drive['path']))
                self.erase_logger.info("Started cleaning drive: {}".format(a_drive['dev_path']))
                self.progress_ipc.send_msg(100.0 * i / num_data_drives)
                self.urgentIpc.send_msg("Cleaning drive: {} of {}....".format(i, num_data_drives))
                g = gevent.spawn(dw.reformat_me, erase_logger=self.erase_logger)
                jobs.append(g)
                gevent.sleep(0)
                i += 1
        self.logger.debug("Waiting for the reformatting to complete")
        self.erase_logger.info("Waiting for the reformatting to be completed")

        gevent.joinall(jobs)
        self.erase_logger.info("End of Clean All Data: Duration(hh:mm:ss) {}".
                               format(timedelta(seconds=int(time.time()-start))))
        self.erase_logger.info("*" * 80)
        self.urgentIpc.send_msg("Done cleaning drives.. reindexing")
        resync_db_to_disks(info_only=False, force=True)
        self.urgentIpc.send_msg("System OK")
        if control_services:
            self._start_services()
        if exit_process:
            self._exit_process()

    def _secure_erase_alldrives(self, exit_process=False, pattern='dod'):
        """
        Main function to securely clean data disks.
        It reformats all the drives, drops the files collection and zeroes out the recordings info

        :param exit_process: Indicates if you need to exit the parent process or not
        :return:
        """
        self.logger.debug("Starting erase with pattern {} in secure erase all drives".format(pattern))
        self.burnside_db.system_settings.update_one({}, {"$set": {'system_state': 'restarting'}})
        self.urgentIpc.send_msg("Secure erase all drives")
        self.logger.debug("Stopping cleanup")
        self.erase_logger.info("Start of Secure Erase of Data drives")
        self.erase_logger.info("Stopping the Capture and Cleanup")
        control_process('cleanup', 'stop')
        self._reset_files_and_recordings()

        drives = self.burnside_db.drives.find({'mounted': True})
        num_data_drives = drives.count() - 1  # ignore system disk
        self.erase_logger.info("Number of drives to be erased : {}".format(num_data_drives))
        i = 1
        jobs = []
        start = time.time()
        for a_drive in drives:
            if "DATA_" in a_drive['name']:
                if "SYS_DATA" in a_drive['name']:
                    continue
                # the drive is a data drive
                dw = driveWrapper(self.logger, self.burnside_db, a_drive['dev_path'])
                self.logger.debug("Cleaning the drive: {}".format(a_drive['path']))
                self.erase_logger.info("Started Secure Erase on drive: {} with {}"
                                       .format(a_drive['dev_path'], dw.serial_no or "Serial Number: Unknown"))
                self.progress_ipc.send_msg(100.0 * i / num_data_drives)
                self.urgentIpc.send_msg("Started secure erase of drive: {} of {}....".format(i, num_data_drives))
                g = gevent.spawn(dw.secure_clean_me, erase_logger=self.erase_logger, pattern=pattern)
                jobs.append(g)
                gevent.sleep(0)
                i += 1
        notify_event = gevent.spawn(self._notify_cleanup_status)
        self.logger.debug("Waiting for the secure erase to be completed")
        self.urgentIpc.send_msg("Secure erase of all {} drives in progress....".format(num_data_drives))
        self.erase_logger.info("Waiting for the secure erase to be completed")
        gevent.joinall(jobs)
        self.erase_logger.info("End of Secure erase. Duration(hh:mm:ss) {}".
                               format(timedelta(seconds=int(time.time() - start))))
        self.erase_logger.info("*" * 80)
        try:
            gevent.kill(notify_event)
        except Greenlet.GreenletExit:
            pass

        self.urgentIpc.send_msg("Done secure erase of drives.")
        self.burnside_db.system_settings.update_one({}, {"$set": {'system_state': 'ok'}})
        self.urgentIpc.send_msg("System OK")
        self._halt_main_services()
        self._start_services(start_cleanup=False)
        if exit_process:
            self._exit_process()

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to restart services')
    def restartAll(self):
        """
        .. http:post:: /sys/20141030/restartAll

            Restarts all the services on cstor

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        rv = self._restart_services()

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to restart the download service')
    def restartPcap(self):
        """
        .. http:post:: /sys/20141030/restartPcap

            Restarts the pcap download bubble

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        for i in xrange(Consts.PCAP_PROCESS_COUNT):
            control_process('pcap-{}'.format(i), 'stop')
            control_process('pcap-{}'.format(i), 'start')

        return {"status": "restarted the download bubble"}

    def _start_services(self, start_cleanup=True):
        """
        A utility method to start the services -
        only need to start the key processes as other processes are dependent on them
        :return:
        """
        rc = 0
        self.logger.debug("starting: services")
        process_list = ["session_app", "rt", "queryapp", "ipmi_tool", "snmp"]
        if start_cleanup:
            process_list.append('cleanup')
        for prc in process_list:
            self.logger.debug("checking if process {} is running".format(prc))
            if process_is_running(prc):
                continue
            control_process(prc, 'start')
        start_mongod()
        return rc

    def _restart_services(self):
        """
        A utility method to restart the services so it can be used from multiple interface functions
        :return:
        """
        wr = self.burnside_db.system_settings.update_one(
            {},
            {"$set": {'system_state': 'restarting'}})
        self.urgentIpc.send_msg("Services restarting... please wait")

        self._halt_main_services()
        self.logger.debug("_halt_main_services() services returned")
        # by exiting we let systemd start all the process

        # Not sure why it would ever happen but if admin_app when nprobe
        # processes and the balancer processes are stopped now, it eventually
        # causes issue while running the qcu utility [ /opt/qcu/qcu64e ].
        # The following error is also seen in admin_app logs when the API
        # restartAll is invoked:
        # admin_app: Socket error(32): Broken pipe
        # So, do not call _halt_cprobe_services() just before admin_app exits
        gevent.spawn(self._exit_process)
        return

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to reboot a system')
    def rebootSystem(self):
        """
        .. http:post:: /sys/20141030/rebootSystem

            Reboots the server

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        # Do not call this function directly from other places.
        # It can cause bottleapp errors.
        try:
            # Stopping all probe services is required for the reboot to succeed
            capture_mode = self.burnside_db.system_settings.find_one({}, {"_id": False, "capture_mode": True})
            if capture_mode and capture_mode.get('capture_mode') == 'cprobe':
                cprobe = cProbeControl(self.burnside_db, self.logger)
                cprobe.stop(True)
        except Exception as e:
            self.logger.error("Failed to stop services before system reboot {}".format(str(e)))

        self.logger.warn("System reboot invoked at " + time.ctime())
        gevent.spawn(os.system, "reboot")
        return {'status': 'success', 'msg': 'Initiated system reboot'}

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to clean the logs')
    def shutdownSystem(self):
        """
        .. http:post:: /sys/20141030/shutdownSystem

            Shuts down the server

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        self.logger.warn("System shutdown invoked by a user at: " + time.ctime())
        gevent.spawn(os.system, "shutdown -h 1 'initiated shutdown from admin app'")
        return {'status': 'success', 'msg': 'Initiated system shutdown'}

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to clean the logs')
    def cleanLogs(self):
        """
        .. http:post:: /sys/20141030/cleanLogs

            Removes old logs from the log directory to free up system disk space

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        dirs = ['nginx', 'upstart', 'mongodb']
        for d in dirs:
            rm_cmd = "rm -f /var/log/{}/*.gz ".format(d)
            p = gevent.subprocess.Popen(rm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            sout, serr = p.communicate()
            rc = p.returncode
            if rc != 0 or serr != '':
                self.logger.debug("Cleanup files RC={} stderr: {}".format(rc, serr))

    def _download_logs(self):

        self.burnside_db.system_settings.update_one({}, {"$set": {'log_collection': 'in-progress'}})
        my_ip = hostname_ip()

        f_name = "cstor_{}_logs_{}.tar".format(my_ip,
                                                  time.strftime('date_%Y_%m_%d_time_%H_%M_%S', time.gmtime()))
        # dump journalctl files into a regular file
        dump_journal_file = "journal.log"
        tmp_directory = "/tmp"
        journal_cmd = "journalctl > {}/{}".format(tmp_directory, dump_journal_file)
        rc, serr, sout = run_cmd(journal_cmd, True)

        # Continue the diagnostics even if the journalctl fails
        if rc != 0 or serr != '':
            with open("{}/{}".format(tmp_directory, dump_journal_file), "a") as fp:
                fp.write("Failed to dump journal file ({}): rc: {}; serr: {} "
                         "sout: {}".format(journal_cmd, rc, serr, sout))

        # Create the bios/motherboard information
        dump_dmidecode_info = "dmidecode_info.txt"
        dmidecode_cmd = "dmidecode > {}/{}".format(tmp_directory, dump_dmidecode_info)
        rc, serr, sout = run_cmd(dmidecode_cmd, True)
        if rc != 0 or serr != '':
            with open("{}/{}".format(tmp_directory, dump_dmidecode_info), "a") as fp:
                fp.write("Failed to dump dmidecode file ({}): rc: {}; serr: {} "
                         "sout: {}".format(dmidecode_cmd, rc, serr, sout))

        dump_disk_info = "disk_info.txt"
        diskinfo_cmd = "/sbin/hdparm -I /dev/sd[a-z] > {}/{}".format(tmp_directory, dump_disk_info)
        rc, serr, sout = run_cmd(diskinfo_cmd, True)
        if rc != 0 or serr != '':
            with open("{}/{}".format(tmp_directory, dump_disk_info), "a") as fp:
                fp.write("Failed to dump disk info file ({}): rc: {}; serr: {} "
                         "sout: {}".format(diskinfo_cmd, rc, serr, sout))

        tar_contents = {}
        tar_contents[tmp_directory] = [dump_journal_file, dump_dmidecode_info, dump_disk_info]
        tar_contents['/var'] = ['--exclude="log/journal"', 'log']
        tar_contents['/home/cpacket/.cstor'] = ['.']
        tar_contents['/home/cpacket/packages/cstordep/'] = ['version.txt']

        rc, serr, sout = tar_files(tarfile_name=f_name, file_info=tar_contents, use_gevent=True)
        if rc == 1:
            # Continue as this (rc=1) is a warning due to change in file content during tar
            self.logger.debug("Warning because of file change during execution. "
                              "rc: {}, serr: {}, sout: {}".format(rc, serr, sout))
        elif rc != 0 or serr != '':
            self._log_and_abort(500, "Failed to tar log files: rc: {}; serr: {} sout: {}".format(rc, serr, sout))

        try:
            os.remove(os.path.join(tmp_directory, dump_journal_file))
        except OSError as e:
            self.logger.debug("Failed to remove files ({}) error: {}".format(dump_journal_file, e))

        zip_cmd = "gzip -f {} ".format(f_name)
        rc, serr, sout = run_cmd(zip_cmd, True)
        if rc != 0 or serr != '':
            self._log_and_abort(500, "Failed to zip file ({}): rc: {}; serr: {} sout: {}".format(zip_cmd,
                                                                                                 rc, serr, sout))
        try:
            f_name += ".gz"
            to_file = os.path.join(self.html_root, f_name)
            mv_cmd = 'mv {} {}'.format(f_name, to_file)
            rc, serr, sout = run_cmd(mv_cmd, True)
            if rc != 0 or serr != '':
                self._log_and_abort(500, "Failed to move file ({}): rc: {}; serr: {} sout: {}".format(
                    mv_cmd, rc, serr, sout))
        except OSError as e:
            self._log_and_abort(500, "Failed to move file ({}) error: {}".format(f_name, e))
        try:
            return bottle.static_file(f_name, root=self.html_root, download=f_name)
        finally:
            self.burnside_db.system_settings.update_one({}, {"$set": {'log_collection': 'idle'}})
            os.remove(os.path.join(self.html_root, f_name))

    @cp_auth([settings.ADMIN_ROLE, settings.READONLY_ROLE], 'Have to be an admin/read-only to download system logs')
    def downloadLogs(self):
        """
        .. http:post:: /sys/20141030/downloadLogs

            Collects, zip and downloads all the log files

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """

        if diag_log_lock.locked():
            self._log_and_abort(400, "Diagnostic collection is in progress. Try again shortly")

        with diag_log_lock:
            try:
                return self._download_logs()
            except Exception:
                self.burnside_db.system_settings.update_one({}, {"$set": {'log_collection': 'idle'}})
                raise


    @cp_auth([settings.ADMIN_ROLE, settings.READONLY_ROLE], 'Have to be an admin/read-only  to download audit logs')
    def downloadAuditLogs(self):
        """
        .. http:post:: /sys/20141030/downloadAuditLogs

            Collects, zip and downloads all the audit log files

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        my_ip = hostname_ip()

        f_name = "cstor_{}_audit_logs_{}.tar".format(my_ip,
                                                  time.strftime('date_%Y_%m_%d_time_%H_%M_%S', time.gmtime()))
        audit_logs_path= "/var/log/nginx"
        audit_log_files = [f for f in os.listdir(audit_logs_path) if f.startswith("audit.log")]

        # tar all audit log files together
        rc, serr, sout = tar_files(tarfile_name=f_name, file_info={audit_logs_path: audit_log_files}, use_gevent=True)
        if rc != 0 or serr != '':
            self._log_and_abort(500, "Failed to tar audit logs({}): rc: {}; serr: {} sout: {}".format(audit_log_files,
                                                                                                      rc, serr, sout))
        zip_cmd = "gzip -f {} ".format(f_name)
        rc, serr, sout = run_cmd(zip_cmd, True)
        if rc != 0 or serr != '':
            self._log_and_abort(500, "Failed to zip file ({}): rc: {}; serr: {} sout: {}".format(zip_cmd, rc, serr, sout))
        try:
            f_name += ".gz"
            to_file = os.path.join(self.html_root, f_name)
            mv_cmd = 'mv {} {}'.format(f_name, to_file)
            rc, serr, sout = run_cmd(mv_cmd, True)
            if rc != 0 or serr != '':
                self._log_and_abort(500, "Failed to move file ({}): rc: {}; serr: {} sout: {}".format(mv_cmd, rc, serr, sout))
        except OSError as e:
            self._log_and_abort(500, "Failed to move file ({}) error: {}".format(f_name, e))
        try:
            return bottle.static_file(f_name, root=self.html_root, download=f_name)
        finally:
            os.remove(os.path.join(self.html_root, f_name))

    @cp_auth([settings.ADMIN_ROLE, settings.READONLY_ROLE], 'Have to be an admin/read-only to download configuration')
    def downloadConfig(self):
        """
        .. http:post:: /sys/20141030/downloadConfig

           Download the system configuration, stores it as a json file

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        rm_cmd = "rm -f {}/cstor_{}_*.json ".format(self.html_root, hostname_ip())
        p = gevent.subprocess.Popen(rm_cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, shell=True)
        sout, serr = p.communicate()
        rc = p.returncode
        if rc != 0 or serr != '':
            self.logger.debug("Cleanup files RC={} stderr: {}".format(rc, serr))
        the_version = "missing"
        try:
            with open(os.path.join(self.main_dir, Consts.UPDATE_VERSION_FILE), 'r') as version_fd:
                for line in version_fd.readlines():
                    if "version:" in line:
                        the_version = line.split('\n')[0].split()[1]
        except IOError:
            self.logger.error("could not find version in version file: {}".
                              format(os.path.join(self.main_dir, Consts.UPDATE_VERSION_FILE)))
            pass

        config = {
            'version': the_version,
            'users': [],
            'jobs': [],
            'groups': [],
            'recordings': [],
            'active_recordings': [],
            'system_settings': {},
            'tacacs_settings': {},
            'static_route_settings': [],
            'snmp': [],
            'acl_configuration': []
        }
        for m in self._user_management.list_users():
            config['users'].append(m.as_dict())
        config['users'].append(self._user_management.get_default_recording_user_for_config().as_dict())
        for m in self.burnside_db.jobs.find({}):
            config['jobs'].append(m)
        for m in self.burnside_db.groups.find({}):
            config['groups'].append(m)
        for m in self.burnside_db.recordings.find({}):
            config['recordings'].append(m)
        for m in self.burnside_db.active_recordings.find({}, {"_id": False}):
            config['active_recordings'].append(m)
        for m in self.burnside_db.static_route_settings.find({}, {'_id': False}):
            config['static_route_settings'].append(m)
        for m in self.burnside_db.snmp.find({}, {'_id': False}):
            config['snmp'].append(m)
        for m in self.burnside_db.acl_configuration.find({}, {'_id': False}):
            config['acl_configuration'].append(m)

        system_settings = self.burnside_db.system_settings.find_one({}, {"_id": False})
        system_settings = self._remove_stats_db_from_system_settings(system_settings)
        snap_id = extract_parameter('snap_id', ParameterType.string).value
        if snap_id is not None:
            system_settings['snap_id'] = snap_id
        elif 'snap_id' not in system_settings:
            system_settings['snap_id'] = ''
        config.update({'system_settings': system_settings})
        tacacs_settings = self.burnside_db.tacacs_settings.find_one({}, {'_id': False})
        config.update({'tacacs_settings': tacacs_settings})

        ntp_servers = self.ubCfg.ListNTPServers()
        config['ntp_servers'] = ntp_servers
        management_interface_name = self.ubCfg.GetManagementInterfaceName()
        ifcfg_management_interface = self.ubCfg.GetNetworkConfiguration(management_interface_name)
        config['management_interface_1'] = ifcfg_management_interface

        t_str = time.strftime('gmt_%s_date_%Y_%m_%d_time_%H_%M_%S', time.gmtime())
        f_name = time.strftime('cstor_{}_cfg_{}.json'.format(hostname_ip(), t_str))
        config_file = os.path.join(self.html_root, f_name)

        with open(config_file, "w") as f:
            json.dump(config, f, ensure_ascii=False, cls=MyJsonEncoder)

        return bottle.static_file(f_name, root=self.html_root, download=f_name)

    @cp_auth([settings.ADMIN_ROLE, settings.READONLY_ROLE], 'Have to be an admin/read-only  to download disk details')
    def downloadDiskDetails(self):
        """
        .. http:post:: /sys/20141030/downloadDiskDetails

            Collect the disk details and provide

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        f_name = "cstor_{}_disk_details.txt".format(hostname_ip())
        cmd = '/bin/lsblk > {}'.format(f_name)
        rc, serr, sout = run_cmd(cmd, True)
        if rc != 0 or serr != '':
            self._log_and_abort(
                500,
                "Failed to fetch lsblk details ({}): rc: {}; serr: {} sout: {}".format(cmd, rc, serr, sout)
            )

        cmd = '/sbin/hdparm -I /dev/sd[a-z] >> {}'.format(f_name)
        rc, serr, sout = run_cmd(cmd, True)
        if rc != 0 or serr != '':
            self._log_and_abort(
                500,
                "Failed to fetch disk details ({}): rc: {}; serr: {} sout: {}".format(cmd, rc, serr, sout)
            )

        try:
            to_file = os.path.join(self.html_root, f_name)
            mv_cmd = 'mv {} {}'.format(f_name, to_file)
            rc, serr, sout = run_cmd(mv_cmd, True)
            if rc != 0 or serr != '':
                self._log_and_abort(
                    500,
                    "Failed to move file ({}): rc: {}; serr: {} sout: {}".format(mv_cmd, rc, serr, sout)
                )
        except OSError as e:
            self._log_and_abort(500, "Failed to move file ({}) error: {}".format(f_name, e))

        try:
            return bottle.static_file(f_name, root=self.html_root, download=f_name)
        finally:
            os.remove(os.path.join(self.html_root, f_name))

    def _remove_stats_db_from_system_settings(self, settings):
        """Remove stats db information, as it would include a plaintext password. Don't want to do this, so require the
        user to re-enter upon restoring a config.

        :param settings: sytem settings dict
        :return: system settings dict with stats db entries removed
        """
        settings.pop('stats_db_user', None)
        settings.pop('stats_db_pswd', None)

        return settings

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to upload a system backup')
    def uploadSystemBackup(self):
        """
        .. http:post:: /sys/20141030/uploadSystemBackup

           uploads a system backup configuration file and returns a handle so that restore system config can use it

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        rv = {'status': 'success'}
        min_version = 0

        data = request.files.file

        if data and data.file:
            conf_file = os.path.join('/tmp', data.filename)
            data.save(conf_file, overwrite=True)
            # raw = data.file.read() # This is dangerous for big files
            try:
                with open(conf_file, "r") as f:
                    settings = json.load(f)
                ver_str = settings.get('version')
                if ver_str is None:
                    rv['status'] = 'error'
                    rv['message'] = 'File version is too old.  Unable to restore.'
                    raise bottle.HTTPResponse(status=400, body=rv['message'])
                ver = ver_str.split('.')
                version = float(int(ver[0]) + float(ver[1])/10)
                if version < 16.2:
                    rv['status'] = 'error'
                    rv['message'] = 'File version ({}) is too old has to be newer than 16.2.  Unable to restore.'.\
                        format(ver_str)
                    raise bottle.HTTPResponse(status=400, body=rv['message'])
            except (ValueError, AttributeError):
                rv['status'] = 'error'
                rv['message'] = 'Uploaded file is not valid.  Unable to restore.'
                raise bottle.HTTPResponse(status=400, body=rv['message'])
            restoreKey = self.burnside_db.restore_files.insert({'filename': conf_file})
            rv['message'] = "Received a valid system settings file: {}".format(data.filename)
            # This restore key will be passed to restoreSystemBackup
            rv['restoreKey'] = str(restoreKey)
            return rv
        else:
            rv['status'] = 'error'
            rv['message'] = 'Missing file name in request.'
            raise bottle.HTTPResponse(status=400, body=rv['message'])

    def _tail_log(self, body, log, lines=100):
        if log is not None:
            cmd = 'tail -n {} {}'.format(lines, log)
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = p.communicate()[0]
            p.stdout.close()
            i = 1
            if body is not None:
                body.put_nowait('Tail of log file: {} (latest on top)\n'.format(log))
            for line in reversed(output.splitlines()):
                if body is not None:
                    body.put_nowait('{}: '.format(i))
                    body.put_nowait(line.rstrip())
                    body.put_nowait('\n')
                i += 1
            if body is not None:
                body.put_nowait(StopIteration)

    def _journalctl(self, body, process, lines=100):
        if process is not None:
            cmd = 'journalctl -n {} --output=json -u {}'.format(lines, process)
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = p.communicate()[0]
            p.stdout.close()
            i = 1
            if body is not None:
                body.put_nowait('Journalctl for: {} (latest on top)\n'.format(process))
            for line in reversed(output.splitlines()):
                jline = json.loads(line)
                if body is not None:
                    body.put_nowait('{}: '.format(i))
                    rtime = float(jline.get('__REALTIME_TIMESTAMP'))/1e6
                    stime = time.strftime('%m/%d/%Y %H:%M:%S',
                                          time.gmtime(rtime))
                    body.put_nowait('{} ({}): '.format(stime, rtime))
                    body.put_nowait('{}: '.format(jline.get('SYSLOG_IDENTIFIER')))
                    body.put_nowait('{} '.format(jline.get('MESSAGE')))
                    body.put_nowait('\n')
                i += 1
            if body is not None:
                body.put_nowait(StopIteration)

    @cp_auth([settings.ADMIN_ROLE, settings.READONLY_ROLE], 'Have to be an admin/read-only to read syslog')
    def getSyslog(self):
        """
        .. http:post:: /sys/20141030/getSyslog
            Example:  https://<cstor-ip>/sys/20141028/getSyslog?logFileName=upstart/stats.log
           Runs tail and journal command over a log and sends the info back
           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        rv = {'status': 'success'}
        (process, status, error) = extract_parameter('logFileName', param_type=ParameterType.string)
        if not process:
            raise bottle.HTTPResponse(status=status, body=error)

        (lines, status, error) = extract_parameter('lines', param_type=ParameterType.int)
        if not lines:
            lines = 100

        if lines > LOG_LINES_LIMIT:
            lines = LOG_LINES_LIMIT

        if process == 'syslog':
            body = queue.Queue()
            _ = gevent.spawn(self._tail_log, body, "/var/log/syslog", lines)
        elif process == "disk_clean":
            body = queue.Queue()
            _ = gevent.spawn(self._tail_log, body, SECURE_ERASE_LOG, lines)
        else:
            body = queue.Queue()
            _ = gevent.spawn(self._journalctl, body, process, lines)

        return body

    def _doRestore(self, body, filename):
        """
            A method to do the actual system settings restore
            :param s:
            :param body:
            :return:
        """
        try:
            with open(filename, "r") as f:
                config = json.load(f)
        except OSError:
            if body is not None:
                body.put_nowait("Error opening {} \n".format(filename))
                body.put_nowait(StopIteration)
            return
        version = config.get('version')
        if version is None:
            if body is not None:
                body.put_nowait("filename is not a valid configuration file\n")
                body.put_nowait(StopIteration)
            return
        if body is not None:
            body.put_nowait("stopping processes\n")
        self._halt_main_services()
        self._halt_cprobe_services()

        if body is not None:
            body.put_nowait("cleaning drives\n")
        self.logger.debug("Cleaning all drives")
        self._clean_all_drives()

        if body is not None:
            body.put_nowait("updating users\n")
        self.logger.debug("deleting all users")
        for u in self._user_management.list_users():
            # the delete user has a protection against deleting cpacket and the last admin
            try:
                self._user_management.remove_user(u.name)
                delete_user_files(u.name, self._user_management, self.logger)
            except UserManagementError:
                pass

        self.logger.debug("inserting users")
        users = config.get('users')
        try:
            self._user_management.restore_users(users)
        except UserManagementError as err:
            self.logger.error('Failed to restore users: {}'.format(str(err)))

        self.logger.debug("updating system settings")
        self.burnside_db.system_settings.drop()
        new_system_settings = config.get('system_settings')
        if new_system_settings is not None:
            self.burnside_db.system_settings.insert(new_system_settings)

        new_ntp_servers = config.get('ntp_servers')
        if new_ntp_servers is not None and new_ntp_servers:
            self._set_ntp_configuration(new_ntp_servers)

        self.logger.debug('updating tacacs+ settings')
        self.burnside_db.tacacs_settings.drop()
        new_tacacs_settings = config.get('tacacs_settings')
        if new_tacacs_settings is not None:
            self.burnside_db.tacacs_settings.insert(new_tacacs_settings)
            auth_enabled = new_tacacs_settings.get('enabled', False)
            if auth_enabled:
                ext_auth_ctrl = ExternalAuthController(self.logger)
                ext_auth_ctrl.enableExternalAuth()

        self.logger.debug('updating static route settings')
        self.burnside_db.static_route_settings.drop()
        new_static_route_settings = config.get('static_route_settings')
        if new_static_route_settings is not None:
            for route in new_static_route_settings:
                self.burnside_db.static_route_settings.insert(route)

        self.logger.debug('updating snmp settings')
        self.burnside_db.snmp.drop()
        new_snmp = config.get('snmp')
        if new_snmp is not None:
            for entry in new_snmp:
                self.burnside_db.snmp.insert(entry)

        self.logger.debug('updating ACL settings')
        self.burnside_db.acl_configuration.drop()
        new_acl_configuration = config.get('acl_configuration')
        if new_acl_configuration is not None:
            for entry in new_acl_configuration:
                self.burnside_db.acl_configuration.insert(entry)

        self.logger.debug('updating management interface settings')
        new_management_interface_1_settings = config.get('management_interface_1')
        new_management_interface_2_settings = config.get('management_interface_2')
        if new_management_interface_1_settings is not None:
            self.ubCfg.set_network_configuration(new_management_interface_1_settings)
        if (new_management_interface_2_settings is not None and 'source' in new_management_interface_2_settings
                and (new_management_interface_2_settings['source'] == 'static' or new_management_interface_2_settings['source'] == 'dhcp')):
            self.ubCfg.set_network_configuration(new_management_interface_2_settings)
        else:
            self.ubCfg.set_network_configuration({})

        self.logger.debug("inserting jobs")
        self.burnside_db.jobs.drop()
        new_col = config.get('jobs')
        if new_col is not None:
            for n in new_col:
                _dict = {}
                for k in n:
                    if k in ['_id', 'userId', 'jobId', 'groupId']:
                        _dict[k] = ObjectId(n[k])
                    else:
                        _dict[k] = n[k]
                self.burnside_db.jobs.insert(_dict)

        self.logger.debug("inserting groups")
        self.burnside_db.groups.drop()
        new_col = config.get('groups')
        if new_col is not None:
            for n in new_col:
                _dict = {}
                for k in n:
                    if k in ['_id', 'userId', 'jobId', 'groupId']:
                        _dict[k] = ObjectId(n[k])
                    else:
                        _dict[k] = n[k]
                self.burnside_db.groups.insert(_dict)

        self.logger.debug("inserting recordings")
        self.burnside_db.recordings.drop()
        new_col = config.get('recordings')
        if new_col is not None:
            for n in new_col:
                _dict = {}
                current_time = time.time()
                try:
                    n['filesInfo']["totalSize"] = 0
                    n['filesInfo']["lastSpeed"] = 0
                    n['filesInfo']["startTime"] = current_time
                    n['filesInfo']["endTime"] = current_time
                    n['filesInfo']["fileCount"] = 0
                    del n['filesInfo']["last_update_time"]
                    del n['filesInfo']["lastFileSize"]
                except KeyError:
                    pass
                for k in n:
                    if k in ['_id', 'userId', 'jobId', 'groupId']:
                        _dict[k] = ObjectId(n[k])
                    else:
                        _dict[k] = n[k]
                self.burnside_db.recordings.insert(_dict)

        self.logger.debug("inserting active recordings")
        self.burnside_db.active_recordings.drop()
        new_col = config.get('active_recordings')
        if new_col is not None:
            for n in new_col:
                _dict = {}
                for k in n:
                    if k in ['recordingId', 'groupId']:
                        if n[k] is not None:
                            _dict[k] = ObjectId(n[k])
                    else:
                        _dict[k] = n[k]
                self.burnside_db.active_recordings.insert(_dict)

        self.burnside_db.templates.drop()

        capture_mode = self.burnside_db.system_settings.find_one({}, {"_id": False, "capture_mode": True})
        if capture_mode and capture_mode.get('capture_mode') == 'cprobe':
            self.setQSFPModeFromDB()
        else:
            self.burnside_db.system_settings.update_one({}, {"$set": {'qsfp_mode': Consts.QSFP_MODE_UNSUPPORTED}})

        if body is not None:
            body.put_nowait("Finished settings restore - restarting the system\n")
        self.logger.debug("Finished settings restore - restarting the system")
        # We do not need to stop cProbe processes for safely rebooting
        # without panicking kernel. They are already stopped by now.
        os.system("reboot")

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to restore a system backup')
    def restoreSystemBackup(self):
        """
        .. http:post:: /sys/20141030/restoreSystemBackup

           Restores the system from settings backup

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        (restoreKey, status, error) = extract_parameter('restoreKey', ParameterType.string, min_val=1, max_val=255)
        if not restoreKey:
            self._log_and_abort(status, error)
        restore = self.burnside_db.restore_files.find_one({'_id': ObjectId(restoreKey)})

        # start_response('200 OK', [('Content-Type', 'text/html')])
        body = queue.Queue()

        # cmd = 'ping 127.0.0.1 -c 12'
        # p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # g = gevent.spawn(self._doRestore, body, p.stdout, p.stderr)
        self._restoring = True
        g = gevent.spawn(self._doRestore, body, restore.get('filename'))
        return body

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to restore a system backup')
    def restoreSystemBackupWithSnapId(self):
        """
        .. http:post:: /sys/20141030/restoreSystemBackupWithSnapId

        Restores systems from settings backup, with included snap id.

        """
        (restoreKey, status, error) = extract_parameter('restoreKey', ParameterType.string, min_val=1, max_val=255)
        if not restoreKey:
            self._log_and_abort(status, error)
        restore = self.burnside_db.restore_files.find_one({'_id': ObjectId(restoreKey)})

        # Make sure we actually have a snap id, and upsert into database. This is the "temporary snap id" used in
        # verifying that a restore has worked properly.
        (snap_id, status, error) = extract_parameter('snap_id', ParameterType.string)
        if snap_id is None:
            self._log_and_abort(status, error)
        self.burnside_db.system_settings.update({}, {'$set': {'snap_id': snap_id}}, upsert=True)

        self._restoring = True
        g = gevent.spawn(self._doRestore, None, restore.get('filename'))
        return {'status': 0}

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to view snap id.')
    def getSnapId(self):
        """
        .. http:get:: /sys/20141030/getSnapId

        Returns snap_id from system settings.
        """
        if self._restoring:
            self._log_and_abort(404, 'Currently restoring... please wait until system restarts.')

        system_settings = self.burnside_db.system_settings.find_one({})
        if 'snap_id' in system_settings:
            return {'status': 0, 'snap_id': system_settings['snap_id']}
        else:
            return {'status': 0, 'snap_id': ''}

    def getSystemSettings(self):
        """
        .. http:post:: /sys/20141030/getSystemSettings

           Get the system settings

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        rv = {}
        if self.burnside_db.drives.find().count() > 0:
            drives = []
            for drive_data in self.burnside_db.drives.find(
                    {},
                    {"_id": False}):
                drives.append(drive_data)
            rv.update({'drives': drives})
        sys_settings = self.burnside_db.system_settings.find_one({}, {'_id': False})
        sys_settings = self._remove_stats_db_from_system_settings(sys_settings)
        for key in sys_settings:
            rv.update({key: sys_settings.get(key)})
        bottle.response.headers['Content-Type'] = 'application/json'
        return MyJsonEncoder().encode(rv)

    def getFactory(self):
        bottle.response.headers['Content-Type'] = 'application/json'
        return self.burnside_db.system_settings.find_one({}, {'_id': False, 'factory': True})

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to update settings.')
    def updateASingleSystemSetting(self):
        """
        This is a back door option to update a single field in the system settings w/o testing the validity of the value

        Example: curl -k --basic --user cstor:cstorpw
            -X GET "https://10.51.10.209/sys/10/updateASingleSystemSetting?default_download_q_size=1048576"

            https://prod-cstor01/sys/10/updateASingleSystemSetting?num_of_download_threads=1

        :param key:
        :param sys_cfg:
        :param ptype:
        :param val:
        :return:
        """
        for key in request.query:
            val = request.query[key]
            self.logger.debug("Updating system config: {} to: {}".format(key, val))
            self._update_sys_setting_in_db(key, val)
        self._validate_settings()
        return self.getSystemSettings()

    def _validate_settings(self):
        """
        ensure that we don't have conflict between modes - without indexing there are settings which are not valid
        :return:
        """
        system_settings = self.burnside_db.system_settings.find_one()
        if not system_settings.get('index_mode', False):
            self._update_sys_setting_in_db('run_cflow_mode', False)
            self._update_sys_setting_in_db('run_udp_mcast_mode', False)
            self._update_sys_setting_in_db('run_cnat_indexing', False)
        if system_settings.get('run_cflow_mode', False):
            self._update_sys_setting_in_db('run_cnat_indexing', False)
        else:
            self._update_sys_setting_in_db('run_udp_mcast_mode', False)
        if not system_settings.get('run_cnat_indexing', False):
            self._update_sys_setting_in_db('ipar_mode', False)
        if not system_settings.get('ipar_mode', False):
            self._update_sys_setting_in_db('ipar_survey_only', False)

    def _update_sys_setting_in_db(self, key, val):
        """
        a help per method to update a setting in the system setting document
        :param key:
        :param val:
        :return:
        """
        self.logger.debug("Updating system config: {} to: {}".format(key, val))
        if key in Consts.DEFAULT_SETTINGS_TYPES:
            try:
                settings_type = Consts.DEFAULT_SETTINGS_TYPES[key]
                if settings_type is int:
                    val = int(val)
                elif settings_type is bool:
                    if type(True) == type(val):
                        pass
                    elif str(val).lower() in ['true', '1']:
                        val = True
                    elif str(val).lower() in ['false', '0']:
                        val = False
                    else:
                        return None
                elif settings_type is dict:
                    if type(val) is dict:
                        pass
                    elif type(val) in [basestring, str, unicode]:
                        val = json.loads(str(val))
                    else:
                        return None
                elif settings_type is list:
                    if type(val) is list:
                        pass
                    elif type(val) in [basestring, str, unicode]:
                        val = json.loads(str(val))
                    else:
                        return None
                elif settings_type is basestring:
                    pass
                else:
                    # don't handle other data types
                    return None
            except ValueError:
                return None
        wr = self.burnside_db.system_settings.update(
            {},
            {"$set": {key: val}},
            upsert=True)
        if not wr['updatedExisting']:
            self.logger.warn(" updating {} in system config".format(key))
        return val

    def _update_field(self, key, sys_cfg, ptype=None, val=None):
        """
        Updates a single field in the system settings
        :param key:
        :param sys_cfg:
        :param ptype:
        :param val:
        :return:
        """
        if ptype is not None:
            val = extract_parameter(key, ptype).value

        if val is not None:
            self._update_sys_setting_in_db(key, val)
        else:
            self.logger.warn("Skipping ({})".format(key))

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to update system settings.')
    def updateSystemSettings(self):
        """
        .. http:post:: /sys/20141030/updateSystemSettings

            Updates systems settings.
            Performs validation and restarts all the services

            Example:
            curl -v -k --basic --user cstor:cstorpw -X GET "https://10.51.10.234/sys/20141028/updateSystemSettings?ha_cstor=true"

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        self._halt_main_services()
        for key in request.json:
            val = request.json[key]
            self.logger.debug("Updating system config: {} to: {}".format(key, val))
            change = self._update_sys_setting_in_db(key, val)
            if change is not None:
                    if 'ipar_mode' in key:
                        app_cfg.set('mode', 'ipar_mode', str(val))
                    if 'use_compression' in key:
                        app_cfg.set('mode', 'use_compression', str(val))
        self._validate_settings()
        # quitting and letting systemd to restart system for configuration changes to take effect
        gevent.spawn(self._exit_process)
        return {'status': 'success', 'msg': 'Initiated system settings update'}

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to upload a system backup')
    def uploadCnatConfig(self):
        """
        .. http:post:: /sys/20141030/uploadCnatConfig

           Uploads a new cNAT configuration including black 7 white lists

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        cnat_settings = cIpFixSettings(self.logger)
        rv = {'status': 'success'}

        data = request.files.file

        if data and data.file:
            conf_file = os.path.join('/tmp', data.filename)
            data.save(conf_file, overwrite=True)
            rv = cnat_settings.update_cnat_db(conf_file)

            control_process('cstor_snf', 'stop')
            gevent.sleep(1)
            control_process('cstor_snf', 'start')
            return rv
        else:
            rv['status'] = 'error'
            rv['message'] = 'Missing file name in request.'
            raise bottle.HTTPResponse(status=400, body=rv)

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to update SW')
    def uploadNewSwImage(self):
        """
        .. http:post:: /sys/20141030/uploadNewSwImage

           Uploads a new SW update image

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        rv = {'status': 'success'}

        upload = request.files
        if upload and upload.file:
            rv = self.update_mgr.do_upload(upload=upload.file)
            if rv.get('status') == 'ok':
                rv['message'] = 'Image uploaded and validated ({})'.format(upload.file.filename)
                rv['restoreKey'] = str(self.burnside_db.sw_upgrades.insert({'filename': upload.file.filename}))
            else:
                rv['message'] = 'Failed to upload and validate image: {}'.format(upload.file.filename)
            return rv
        else:
            rv['status'] = 'error'
            rv['message'] = 'Missing file name in request.'
            raise bottle.HTTPResponse(status=400, body=rv)

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to update SW')
    def cancelSwUpdate(self):
        """

        """
        rv = self.update_mgr.do_cancel(0)  # API version doesn't matter currently
        return rv

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to update SW ')
    def updateSw(self):
        """
        .. http:post:: /sys/20141030/updateSw

           Restores the system from settings backup

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
        """
        self.urgentIpc.send_msg("System being upgraded it will take 5-10 minutes... ")
        self.logger.debug("SW Update is in progress - halting services")
        self._halt_main_services()
        self._halt_cprobe_services()
        rv = self.update_mgr.do_update()
        if rv.get('status') == 'ok':
            rv['message'] = 'Updating SW - it may take up to 5-10 minutes for the system to restart'
        else:
            rv['message'] = 'Failed to update SW: {}'.format(rv.get('msg'))
        return rv

    @cp_auth([settings.ADMIN_ROLE, settings.READONLY_ROLE], 'Have to be an admin/user to get network configuration')
    def getNetworkConfiguration(self):
        """
        .. http:post:: /sys/20141030/getNetworkConfiguration
            Retrieves the network configuration
           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        managementInterface = self.ubCfg.GetManagementInterfaceName()
        ifCfg = self.ubCfg.GetNetworkConfiguration(managementInterface)
        currentValues = self.ubCfg.GetInterfaceInfoString(ifCfg)
        return {'runtime': currentValues, 'settings': ifCfg}

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to set network configuration')
    def setNetworkConfiguration(self):
        """
        .. http:post:: /sys/20141030/setNetworkConfiguration
            Sets the network configuration
           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        success = False
        errorDict = {}
        retVal = {'success': False}
        if (request.json is not None):
            configuration = request.json
            errorDict = self.ubCfg.set_network_configuration(configuration)
            success = True if errorDict is None else False
            retVal = {'success': success}
        else:
            self._log_and_abort(400, 'Expected Post with Content-Type application/json with configuration object')

        if not success:
            if 'config_error' in errorDict:
                self._log_and_abort(400, 'Expected configuration object with dhcp or source, address, netmask, gateway')
            retVal['errors'] = errorDict
        return retVal

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to enable external authentication servers.')
    def enableTacacs(self):
        # backward compatibility
        return self.enableExternalAuth()

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def disableTacacs(self):
        # backward compatibility
        return self.disableExternalAuth()

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def enableExternalAuth(self):
        """
        .. http:post:: /sys/20141030/enableExternalAuth
            Enables ext authen passthrough, if ext auth servers have been added.

            **Example request**:
            .. sourcecode:: http

                POST /sys/20141030/enableTacacs HTTP/1.1
                Host: 10.1.1.1
                Accept: application/json

            **Example response**:
            .. sourcecode:: http

                HTTP/1.1 200 OK
                Content-Type: application/json

                {
                    "status": "success",
                    "msg": ""
                }

            :resheader Content-Type: application/json
            :resjson string status: Success or failure of the operation
            :resjson string msg: Message

            :statuscode 403: unauthorized to perform the action
        """
        rval = {'status': 'failure', 'msg': ''}
        ext_auth_ctl = ExternalAuthController(self.logger)
        extauth_was_enabled = ext_auth_ctl.enableExternalAuth()
        if extauth_was_enabled:
            self._notifySettingsUpdated()
            rval['status'] = 'success'
        else:
            rval['msg'] = 'Could not enable external authentication'

        return rval

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def disableExternalAuth(self):
        """
        .. http:post:: /sys/20141030/disableExternalAuth
            Disables TACACS+ authen passthrough.

            **Example request**:
            .. sourcecode:: http

                POST /sys/20141030/disableExternalAuth HTTP/1.1
                Host: 10.1.1.1
                Accept: application/json

            **Example response**:
            .. sourcecode:: http

                HTTP/1.1 200 OK
                Content-Type: application/json

                {
                    "status": "success",
                    "msg": ""
                }

            :resheader Content-Type: application/json
            :resjson string status: Success or failure of the operation
            :resjson string msg: Message

            :statuscode 403: unauthorized to perform the action
        """
        rval = {'status': 'failure', 'msg': ''}
        ext_auth_ctl = ExternalAuthController(self.logger)
        extauth_was_disabled = ext_auth_ctl.disableExternalAuth()
        if extauth_was_disabled:
            rval['status'] = 'success'
            self._notifySettingsUpdated()
        else:
            rval['msg'] = 'Could not disable external authentication'

        return rval

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def getTacacsEnabled(self):
        # backward compatibility
        return self.getExternalAuthEnabled()

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def getExternalAuthEnabled(self):
        """
        .. http:get:: /sys/20141030/getExternalAuthEnabled
            Get TACACS+ authen passthrough status.

            **Example request**:
            .. sourcecode:: http

                GET /sys/20141030/getExternalAuthEnabled HTTP/1.1
                Host: 10.1.1.1
                Accept: application/json

            **Example response**:
            .. sourcecode:: http

                HTTP/1.1 200 OK
                Content-Type: application/json

                {
                    "status": "success",
                    "enabled": true
                }

            :resheader Content-Type: application/json
            :resjson string status: Success or failure of the operation
            :resjson boolean enabled: Status of ext authen passthrough
        """
        rval = {'status': 'success'}
        ext_auth_ctl = ExternalAuthController(self.logger)
        extauth_enabled = ext_auth_ctl.enabled
        rval['enabled'] = extauth_enabled

        return rval

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def getTacacsServers(self):
        # backwards compatibility
        return self.getExternalAuthServers()

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def getExternalAuthServers(self):
        """
        .. http:get:: /sys/20141030/getExternalAuthServers
            Get the list of configured external auth servers.

            **Example request**:
            .. sourcecode:: http

                GET /sys/20141030/getExternalAuthServers HTTP/1.1
                Host: 10.1.1.1
                Accept: application/json

            **Example response**:
            .. sourcecode:: http

                HTTP/1.1 200 OK
                Content-Type: application/json

                {
                    "status": "success",
                    "servers": [{
                        "ip": "10.1.1.2",
                        "port": 49,
                        "mode": "pap"}],
                    "tacacs_service_name": "somename"
                }

            :resheader Content-Type: application/json
            :resjson string status: Success or failure of the operation
            :resjson array servers: List of server dictionaries containing "ip", "port", and "mode"
        """
        rval = {'status': 'success'}
        ext_auth_ctl = ExternalAuthController(self.logger)

        ext_auth_servers = ext_auth_ctl.servers
        for server in ext_auth_servers:
            if 'secret' in server:
                del server['secret']
        rval['servers'] = ext_auth_servers
        rval['tacacs_service_name'] = ext_auth_ctl.tacacs_service_name

        return rval

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def setTacacsServers(self):
        # backwards compatibility
        return self.setExternalAuthServers()

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to add external authentication servers.')
    def setExternalAuthServers(self):
        """
        .. http:post:: /sys/20141030/setExternalAuthServers
            Set list of external authentication servers.

            **Example request**:
            .. sourcecode:: http

                POST /sys/20141030/setExternalAuthServers HTTP/1.1
                Host: 10.1.1.1
                Accept: application/json
                Content-Type: application/json

                {
                    "servers": [{
                        "ip": "10.1.1.2",
                        "port": 49,
                        "mode": "pap",
                        "secret": "tacacs_secret1"
                    }, {
                        "ip": "10.1.1.3",
                        "port": 49,
                        "mode": "pap",
                        "secret": "tacacs_secret2"
                    }],
                    "tacacs_service_name": "somename"
                }

            **Example response**:
            .. sourcecode:: http

                HTTP/1.1 200 OK
                Content-Type: application/json

                {
                    "status": "success",
                    "msg": ""
                }

            :reqheader Content-Type: application/json
            :reqjson array servers: List of server dictionaries
            :reqjson string tacacs_service_name: optional String for TACACS+ service name

            :resheader Content-Type: application/json
            :resjson string status: Success or failure of the operation
            :resjson string msg: Message

            :statuscode 400: missing servers parameter
            :statuscode 403: unauthorized, must be admin
        """
        if request.json is None:
            self._log_and_abort(400, 'Expected post with content-type application/json')
        params = request.json
        if 'servers' not in params:
            self._log_and_abort(400, 'Missing parameters.')
        servers = params['servers']
        tacacs_service_name = params.get('tacacs_service_name', None)

        ext_auth_ctl = ExternalAuthController(self.logger)
        servers_were_set = ext_auth_ctl.set_servers(servers)

        service_name_was_set = True
        if tacacs_service_name is not None:
            service_name_was_set = ext_auth_ctl.set_tacacs_service_name(tacacs_service_name)
        # if we set the service we also enable it to avoid double-login (CPKT-10563)
        extauth_was_enabled = ext_auth_ctl.enableExternalAuth()

        rval = {'status': 'failure', 'msg': ''}
        if servers_were_set and service_name_was_set:
            self._notifySettingsUpdated()
            rval['status'] = 'success'
        else:
            self._log_and_abort(400, 'Could not set external authentication servers or TACACS+ service name')

        return rval

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def addTacacsServer(self):
        # backwards compatibility
        return self.addExternalAuthServer()

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to add external authentication servers.')
    def addExternalAuthServer(self):
        """
        .. http:post:: /sys/20141030/addExternalAuthServer
            Add an external auth server to the list of servers.

            **Example request**:
            .. sourcecode:: http

                POST /sys/20141030/addExternalAuthServer HTTP/1.1
                Host: 10.1.1.1
                Accept: application/json
                Content-Type: application/json

                {
                    "server": {
                        "ip": "10.1.1.2",
                        "port": 49,
                        "mode": "pap",
                        "secret": "tacacs_secret"
                }

            **Example response**:
            .. sourcecode:: http

                HTTP/1.1 200 OK
                Content-Type: application/json

                {
                    "status": "success",
                    "msg": ""
                }

            :resheader Content-Type: application/json
            :resjson string status: Success or failure of the operation
            :resjson string msg: Message

            :statuscode 400: missing server parameter or application/json content
            :statuscode 403: unauthorized to perform the action
        """
        if request.json is None:
            self._log_and_abort(400, 'Expected post with content-type application/json')
        params = request.json
        if 'server' not in params:
            self._log_and_abort(400, 'Missing parameters.')
        server = params['server']

        rval = {'status': 'failure', 'msg': ''}
        ext_auth_ctl = ExternalAuthController(self.logger)
        serverWasAdded = ext_auth_ctl.add_server(server)
        if serverWasAdded:
            rval['status'] = 'success'
        else:
            rval['msg'] = 'Could not add external authentication server'

        return rval

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def removeTacacsServer(self):
        # backwards compatibility
        return self.removeExternalAuthServer()

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to remove external authentication servers.')
    def removeExternalAuthServer(self):
        """
        .. http:post:: /sys/20141030/removeExternalAuthServer
            Remove a external authentication server from the list of servers.

            **Example request**:
            .. sourcecode:: http

                POST /sys/20141030/removeExternalAuthServer HTTP/1.1
                Host: 10.1.1.1
                Accept: application/json
                Content-Type: application/json

                {
                    "server": {
                        "ip": "10.1.1.2",
                        "port": 49,
                }

            **Example response**:
            .. sourcecode:: http

                HTTP/1.1 200 OK
                Content-Type: application/json

                {
                    "status": "success",
                    "msg": ""
                }

            :resheader Content-Type: application/json
            :resjson string status: Success or failure of the operation
            :resjson string msg: Message

            :statuscode 400: missing server parameter or application/json content
            :statuscode 403: unauthorized to perform the action
        """
        if request.json is None:
            self._log_and_abort(400, 'Expected post with content-type application/json')
        params = request.json
        if 'server' not in params:
            self._log_and_abort(400, 'Missing parameters.')
        server = params['server']

        rval = {'status': 'failure', 'msg': ''}
        ext_auth_ctl = ExternalAuthController(self.logger)
        serverWasRemoved = ext_auth_ctl.remove_server(server)
        if serverWasRemoved:
            rval['status'] = 'success'
        else:
            rval['msg'] = 'Could not remove external authentication server'

        return rval

    @cp_auth([settings.ADMIN_ROLE, settings.READONLY_ROLE], 'Need admin/user access to perform this operation.')
    def getTimeSource(self):
        """
        .. http:get:: /sys/20141030/getTimeSource
            Get whether the time source is 'PTP' or 'NTP', or no sync source at all.
        :return:
        """
        system_settings = self.burnside_db.system_settings.find_one()
        time_source = system_settings.get('time_source', '')
        rval = {'timeSource': time_source}
        return rval

    @cp_auth([settings.ADMIN_ROLE, settings.READONLY_ROLE], 'Need admin/user access to perform this operation.')
    def getTimeSync(self):
        """
        .. http:get:: /sys/20141030/getTimeSync
            Return time sync information.
        :return:
        """
        settings = {}
        system_settings = self.burnside_db.system_settings.find_one()
        status = 1
        msg = ''
        time_sync = 'no'
        time_source = system_settings.get('time_source', '')
        settings['type'] = time_source
        if time_source == 'PTP':
            if PtpCfg.ptp_status() > -1:
                time_sync = 'yes'
            config = PtpCfg.ptp_get_config()
            settings[time_source] = config
        elif time_source == 'NTP':
            ntp_sync_status = self.ubCfg.GetNTPSyncStatus()
            if isinstance(ntp_sync_status, dict):
                ntp_sync_status = ntp_sync_status.get('leap_status') == 'Normal'
            if ntp_sync_status:
                time_sync = 'yes'
            servers = self.ubCfg.ListNTPServers()
            serverDict = OrderedDict(('server' + str(i), h) for (i, h) in enumerate(servers))

            settings[time_source] = serverDict

        settings['time_sync'] = time_sync
        settings['status'] = status
        settings['msg'] = msg
        return settings

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to update time synchronization')
    def updateTimeSync(self):
        """
        .. http:post:: /sys/20141030/updateTimeSync
            Updates time sync with json request info.
        :return:
        """
        if request.json is None:
            self._log_and_abort(400, 'Expected post with content-type application/json')
        config = request.json

        type = extract_parameter('type', param_type=ParameterType.string, allowGet=False)
        enable = extract_parameter('enable', param_type=ParameterType.bool, allowGet=False)
        if type.value is None or enable.value is None:
            self._log_and_abort(400, 'Missing parameters')

        success = False
        msg = ''
        if type.value == 'PTP':
            domain = extract_parameter('domain', param_type=ParameterType.int, min_val=0, max_val=127, allowGet=False)
            ttl = extract_parameter('ttl', param_type=ParameterType.int, min_val=0, max_val=7, allowGet=False)
            mode = extract_parameter('mode', param_type=ParameterType.string, allowGet=False)
            self.logger.debug("domain {}, ttl {}, mode {}".format(domain, ttl, mode))
            if enable.value and domain.value is not None and ttl.value is not None and mode.value is not None:
                success, msg = self._set_ptp_configuration(domain.value, ttl.value, mode.value)
            elif not enable.value:
                success, msg = self._disable_ptp_configuration()
            else:
                msg = 'Unable to enable PTP, requires "domain" (integer 0-127), ' \
                      '"ttl" (integer 0-7), "mode" ("end2end" or "peer2peer")'
        elif type.value == 'NTP':
            if enable.value and 'servers' in config:
                success, msg = self._set_ntp_configuration(config['servers'])
            elif not enable.value:
                success = self._disable_ntp_configuration()
            else:
                msg = 'Unable to enable NTP, requires "servers" (dictionary of name: ip)'
        else:
            msg = 'Invalid time synchronization type'
        status = 1 if success else 0
        return {'status': status, 'msg': msg}

    @cp_auth([settings.ADMIN_ROLE, settings.READONLY_ROLE], 'Need admin/user access to perform this operation.')
    def getNtpConfiguration(self):
        """
        .. http:post:: /sys/20141030/getNtpConfiguration
            Retrieves NTP configuration
           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        enabled = self.ubCfg.CheckNtpServiceEnabled()
        servers = self.ubCfg.ListNTPServers() if enabled else ['']

        def makeServerDict(serverList):
            return OrderedDict(('server'+str(i), h) for (i, h) in enumerate(serverList))

        serverDict = makeServerDict(servers)
        rVal = {'enabled': enabled}
        if enabled:
            rVal['servers'] = serverDict
        return rVal

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to set Ntp configuration')
    def setNtpConfiguration(self):
        """
        .. http:post:: /sys/20141030/setNtpConfiguration
            Sets NTP configuration
           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        try:
            if request.json is not None:
                configuration = request.json
            else:
                configuration = {}
                self._log_and_abort(400, 'Expected Post with Content-Type application/json with a configuration object')
        except JSONDecodeError:
            configuration = {}
            self._log_and_abort(400, 'Expected Post with Content-Type application/json containing configuration object')
        exitVal, info = self._set_ntp_configuration(configuration)
        if exitVal:
            return {'success': exitVal, 'info': info}
        else:
            return {'success': exitVal, 'errors': info}  # This means to exit.

    def _set_ntp_configuration(self, configuration):
        servers = configuration  # Extract Parameter.
        errorDict = self.ubCfg.SetNtpServers(servers)
        exitVal = False
        if not errorDict:
            exitVal = True
            PtpCfg.ptp_stop()
            self.ubCfg.CallNtpEnableDisable(True)
            self.ubCfg.CallNtpStop()
            self.ubCfg.CallNtpStart()
            info = 'NTP Service Configured and Started.'
            system_settings = self.burnside_db.system_settings.find_one()
            self._update_field('time_source', system_settings, val='NTP')
            return exitVal, info
        return exitVal, errorDict

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to disable Ntp configuration')
    def disableNtpConfiguration(self):
        """
        .. http:post:: /sys/20141030/disableNtpConfiguration
            Disables NTP configuration
           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        return self._disable_ntp_configuration()

    def _disable_ntp_configuration(self):
        disable = False
        self.ubCfg.CallNtpStop()
        enabled = self.ubCfg.CallNtpEnableDisable(disable)
        system_settings = self.burnside_db.system_settings.find_one()
        self._update_field('time_source', system_settings, val='')
        return {'success': enabled}  # This means to exit.


    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def getSessionConfiguration(self):
        """
        .. http:post:: /sys/20141030/getSessionConfiguration

            Retrieves Session configuration

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        system_settings = self.burnside_db.system_settings.find_one()
        defaultMaxSessionDuration = 24 * 60 * 60
        defaultMaxInactivityDuration = 60 * 60
        defaultConfiguration = {
        'local': {
            'scope': 'local',
            'MaxSessionDuration': defaultMaxSessionDuration,
            'MaxInactivityDuration': defaultMaxInactivityDuration
        },
        'tacacs': {
            'scope': 'tacacs+',
            'MaxSessionDuration': defaultMaxSessionDuration,
            'MaxInactivityDuration': defaultMaxInactivityDuration
        },
        'radius': {
            'scope': 'radius',
            'MaxSessionDuration': defaultMaxSessionDuration,
            'MaxInactivityDuration': defaultMaxInactivityDuration
        },
        'userSettings': [
            # , {
            #    'scope': 'user',
            #    'username': 'exampleuser'
            #    'MaxSessionDuration': 24 * 60 * 60,
            #    'MaxInactivityDuration': 30 * 60
            #   }
            ]
        }
        # dev comment.  useful to reset default
        # self._update_sys_setting_in_db('session_configuration', defaultConfiguration)
        sessionConfiguration = system_settings.get('session_configuration', defaultConfiguration)
        # TODO: validate configuration
        response.content_type = 'application/json'
        return json.dumps(sessionConfiguration)

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to set Session configuration')
    def setSessionConfiguration(self):
        """
        .. http:post:: /sys/20141030/setSessionConfiguration

            Sets Session configuration

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        try:
            if request.json is not None:
                configuration = request.json
            else:
                configuration = {}
                self._log_and_abort(400, 'Expected Post with Content-Type application/json with a configuration object')
        except JSONDecodeError:
            configuration = {}
            self._log_and_abort(400, 'Expected Post with Content-Type application/json containing configuration object')

        # TODO: validate configuration
        self._update_sys_setting_in_db('session_configuration', configuration)
        self._notifySettingsUpdated()

        return {'success': True, 'info': 'Session Settings Saved'}

    def _notifySettingsUpdated(self):
        self.infoIpc.send_msg_verbatim({'channel': 'internal', 'cmd': 'settingsUpdated', 'message': {}})

    @cp_auth([settings.ADMIN_ROLE, settings.READONLY_ROLE], 'Need admin/user access to perform this operation.')
    def getPtpConfiguration(self):
        """
        .. http:get:: /sys/20141030/getPtpConfiguration
            Retrieves PTP configuration

        :return:
        """
        enabled = PtpCfg.ptp_is_enabled()
        status = PtpCfg.ptp_status()
        if status == 0:
            _status = 'synchronized'
        else:
            _status = 'not synchronized'

        config = PtpCfg.ptp_get_config()
        if not config:
            config = 'no config found'

        return {'enabled': enabled, 'status': _status, 'PTP': config}

    @cp_auth([settings.ADMIN_ROLE],  'Need admin privileges')
    def setPtpConfiguration(self):
        """
        .. http:post:: /sys/20141030/setPtpConfiguration
            Sets PTP configuration

        :return:
        """
        if request.json is None:
            self._log_and_abort(400, 'Expected post with content-type application/json')
        config = request.json

        domain = extract_parameter('domain', param_type=ParameterType.int, min_val=0, max_val=127, allowGet=False)
        ttl = extract_parameter('ttl', param_type=ParameterType.int, min_val=0, max_val=7, allowGet=False)
        mode = extract_parameter('mode', param_type=ParameterType.string, allowGet=False)
        if domain.value is None or ttl.value is None or mode.value is None:
            self._log_and_abort(400, 'Incorrect parameters')

        success, msg = self._set_ptp_configuration(domain, ttl, mode)
        success = 1 if success else 0

        return {'success': success, 'msg': msg}

    def _set_ptp_configuration(self, domain, ttl, mode):
        success, msg = PtpCfg.ptp_start(domain, ttl, mode)
        if not success:
            return False, msg
        disable = False
        enabled = self.ubCfg.CallNtpEnableDisable(disable)
        system_settings = self.burnside_db.system_settings.find_one()
        self._update_field('time_source', system_settings, val='PTP')

        return True, msg

    @cp_auth([settings.ADMIN_ROLE], 'Need admin privileges')
    def disablePtpConfiguration(self):
        """
        .. http:post:: /sys/20141030/disablePtpConfiguration
            Disables PTP configuration

        :return:
        """
        success, msg = self._disable_ptp_configuration()
        success = 1 if success else 0

        return {'success': success, 'msg': msg}

    def _disable_ptp_configuration(self):
        success, msg = PtpCfg.ptp_stop()
        if not success:
            return False, msg

        system_settings = self.burnside_db.system_settings.find_one()
        self._update_field('time_source', system_settings, val='')

        return True, ''

    @cp_auth([settings.ADMIN_ROLE], 'Admin privileges required')
    def delroute(self):
        """
        .. http:post:: /sys/20141030/delroute
            Delete static route from cStor. Route will no longer come up on startup.

            **Example request**:
            .. sourcecode:: http

                POST /sys/20141030/delroute HTTP/1.1
                Host: 10.0.0.1
                Accept: application/json
                Content-Type: application/json

                {
                    "id": "id_of_route",
                    "ip": "20.0.0.2"
                }

            **Example response**:
            .. sourcecode:: http

                HTTP/1.1 200 OK
                Content-Type: application/json

                {
                    "status": 0,
                    "msg": "Removed route with id <id>"
                }

            :statuscode 400: missing ip/id parameter
            :statuscode 403: unauthorized, need admin
        """
        id = extract_parameter('id', param_type=ParameterType.string).value
        ip = extract_parameter('ip', param_type=ParameterType.string).value

        if id is None or ip is None:
            self._log_and_abort(400, 'Missing parameters id or ip')

        success, id = self.static_route_manager.remove_route(id, ip)
        if success:
            rsp = {'status': 0, 'msg': 'Removed route with id ({})'.format(id)}
        else:
            rsp = {'status': -1, 'msg': 'Failed to remove route.'}

        return rsp

    @cp_auth([settings.ADMIN_ROLE], 'Admin privileges required')
    def addroute(self):
        """
        .. http:post:: /sys/20141030/addroute
            Add static route to cStor. Route will persist on reboot.

            **Example request**:
            .. sourcecode:: http

                POST /sys/20141030/addroute HTTP/1.1
                Host: 10.0.0.1
                Accept: application/json
                Content-Type: application/json

                {
                    "ip": "20.0.1.0",
                    "type": "net",
                    "netmask": "255.255.255.0",
                    "gw": "192.168.0.20",
                    "interface": "m1"
                }

            **Example response**:
            .. sourcecode:: http

                HTTP/1.1 200 OK
                Content-Type: application/json

                {
                    "status": 0,
                    "msg": "Successfully added route",
                    "_id": "id_of_route",
                    "route": {
                        "ip": "",
                        "type": "",
                        "netmask": "",
                        "gw": "",
                        "interface": ""
                    }
                }

            :statuscode 400: missing ip or netmask (if "type": "net")
            "statuscode 403: unauthorized, need admin
        """
        # route parameters
        # route_type of None is equiv. to host
        # ip must always be present.
        # netmask must be present if route_type is net
        # gw must always be present
        route_type = extract_parameter('type', param_type=ParameterType.string).value
        if route_type is None:
            route_type = 'host'
        ip = extract_parameter('ip', param_type=ParameterType.string).value
        gw = extract_parameter('gw', param_type=ParameterType.string).value
        netmask = extract_parameter('netmask', param_type=ParameterType.string).value
        interface = extract_parameter('interface', param_type=ParameterType.string).value
        if ip is None or (netmask is None and route_type == 'net'):
            self._log_and_abort(400, 'Incomplete parameters for route')
        if netmask is not None and route_type == 'host':
            self._log_and_abort(400, 'Netmask cannot be used with route type "host"')
        if interface is None:
            interface = 'm1'
        route_dict = { 'ip': ip,
                       'nm': netmask,
                       'gw': gw,
                       'type': route_type,
                       'interface': interface}

        success, id = self.static_route_manager.add_route(route_dict)
        if success:
            rsp = {'status': 0, '_id': id, 'msg': 'Successfully added route.', 'route': route_dict}
        else:
            rsp = {'status': -1, 'msg': 'Failed to add route ({}).'.format(route_dict)}
        return rsp

    @cp_auth([settings.ADMIN_ROLE],  'Admin privileges required')
    def getroutes(self):
        """
        .. http:get /sys/20141030/getroutes
            Get list of static routes currently set on the cStor.

            **Example request**:
            .. sourecode:: http

                GET /sys/20141030/getroutes HTTP/1.1
                Host: 10.0.0.1
                Accept: application/json

            **Example response**:
            .. sourcecode:: http

                HTTP/1.1 200 OK
                Content-Type: application/json
                {
                    "routes": [
                        {
                            "ip": "1.1.1.1",
                            "type": "",
                            "":
                            ...
                        },
                        {
                            "ip": "1.1.1.2",
                            "": "",
                            ...
                        }
                    ]
                }

            :statuscode 403: unauthorized, need admin
        """
        routes = self.static_route_manager.get_routes()
        if routes is None:
            rsp = {'status': -1, 'msg': 'Failed to find any routes'}
        else:
            rsp = routes
        return rsp

    def _get_ssh(self):
        return {'enabled': self.ssh_config.is_running()}

    def _post_ssh(self, enable):
        if enable:
            self.ssh_config.enable()
        else:
            self.ssh_config.disable()
        return {'status': 'success'}

    @cp_auth([settings.ADMIN_ROLE], 'Admin privileges required.')
    def ssh(self):
        if request.method == 'GET':
            return self._get_ssh()
        elif request.method == 'POST':
            enable = extract_parameter('enable', ParameterType.bool).value
            if enable is None:
                self._log_and_abort(400, "Missing parameter 'enable'.")
            else:
                return self._post_ssh(enable)

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def getSnmpManagerConfiguration(self):
        """
        .. http:post:: /sys/20141030/getSnmpManagerConfiguration

            Retrieves the SNMP manager configuration from the IPMI engine

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        return {"not implemented"}

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def setSnmpManagerConfiguration(self):
        """
        .. http:post:: /sys/20141030/setSnmpManagerConfiguration

            Sets SNMP manager configuration on the IPMI engine

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: HTTP error code

        """
        return {"not implemented"}

    def _enable_snmp(self, version, port, config):
        if version == SNMP_VERSION_V2C:
            community_string = config.get("community_string", SNMP_DEFAULT_COMMUNITY_STRING)
            write_community_string(community_string)
            status = self.snmp_v2c_config.enable(port)
        else:
            securities = config.get("v3_securities", [])
            set_snmp_v3_config(securities=securities, delete=False, logger=self.logger,
                               interface_name=self.ubCfg.GetManagementInterfaceName())
            status = self.snmp_v3_config.enable(port)
        return status

    def _disable_snmp(self, version, port, config):
        if version == SNMP_VERSION_V2C:
            cleanup_snmp_v2c_config()
            status = self.snmp_v2c_config.disable()
        else:
            securities = config.get('v3_securities', [])
            set_snmp_v3_config(securities=securities, delete=True, logger=self.logger,
                               interface_name=self.ubCfg.GetManagementInterfaceName())
            self.logger.info('Restarting SNMP service...')
            ProcessHandler.restart(port)
            delete_securities_from_usm_table(securities, port, logger=self.logger)
            cleanup_snmp_v3_config()
            status = self.snmp_v3_config.disable()
        return status

    def _init_default_snmp(self):
        """Initialize snmp config with default settings if snmp config is not set.
        """
        projection = {'snmp.enabled': True, 'snmp_v3.enabled': True, '_id': False}
        snmp_settings = self.burnside_db.system_settings.find_one({}, projection=projection)
        config = self.burnside_db.snmp.find_one(projection={'_id': False})
        if config:
            self.snmp_dict = decode_configuration(config)
        else:
            self.snmp_dict = {}
        self.logger.info('Initial configuration : {}'.format(self.snmp_dict))
        if self.snmp_dict:
            port = self.snmp_dict.get('port', SNMP_DEFAULT_PORT)
            if snmp_settings and snmp_settings.get('snmp', {}).get('enabled'):
                v2c_config = {
                    "community_string": self.snmp_dict.get("community_string", SNMP_DEFAULT_COMMUNITY_STRING)
                }
                self._enable_snmp(SNMP_VERSION_V2C, port, v2c_config)
            else:
                self._disable_snmp(SNMP_VERSION_V2C, port, config=None)

            v3_config = {"v3_securities": self.snmp_dict.get('v3_securities', [])}
            if snmp_settings and snmp_settings.get('snmp_v3', {}).get('enabled'):
                self._enable_snmp(SNMP_VERSION_V3, port, v3_config)
            else:
                self._disable_snmp(SNMP_VERSION_V3, port, v3_config)
        else:
            doc = {'snmp.enabled': True, 'snmp_v3.enabled': False}
            self.burnside_db.system_settings.update({}, {'$set': doc}, upsert=True)
            v2c_config = {
                "community_string": SNMP_DEFAULT_COMMUNITY_STRING,
                "port": SNMP_DEFAULT_PORT,
                'hash_revision': HASH_REVISION_2,
            }
            self.burnside_db.snmp.update({}, {'$set': encode_configuration(v2c_config)}, upsert=True)
            self._enable_snmp(SNMP_VERSION_V2C, SNMP_DEFAULT_PORT, v2c_config)

        # ensure that the member snmp_dict reflects saved config
        config = self.burnside_db.snmp.find_one(projection={'_id': False})
        if config:
            self.snmp_dict = decode_configuration(config)

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def getSnmpAgentConfiguration(self):
        """
        .. http:get:: /sys/20141030/getSnmpAgentConfiguration

            Retrieves SNMP agent configuration from the db

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: SNMP agent configuration

        """
        ret_val = {
            'status': -1,
            'message': '--'
        }
        snmp_configuration = self.burnside_db.snmp.find_one(projection={'_id': False})
        self.logger.debug("snmp Configuration : {}".format(snmp_configuration))
        try:
            if snmp_configuration:
                ret_val['config'] = decode_configuration(snmp_configuration)
            else:
                ret_val['config'] = {'community_string': SNMP_DEFAULT_COMMUNITY_STRING, 'port': SNMP_DEFAULT_PORT}

            if self.engine_id:
                ret_val['config']['engine_id'] = self.engine_id
            else:
                self.engine_id = SECURITY_ENGINE_MAC_ADDR_FORMAT.format(
                    mac=self.ubCfg.GetNetworkConfiguration(self.ubCfg.GetManagementInterfaceName()
                                                           ).get('Hwaddr', '')).replace(":", "").upper()
                ret_val['config']['engine_id'] = self.engine_id
            ret_val['message'] = 'Success'
            ret_val['status'] = 0
        except (TypeError, ValueError, AttributeError):
            self.logger.error("Exception during SNMP configuration fetch {}".format(traceback.format_exc()))
            response.status = 400
            ret_val['message'] = 'Failed to retrieve SNMP configuration'
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def setSnmpCommonConfiguration(self):
        """
        .. http:post:: /sys/20141030/setSnmpCommonConfiguration

            Sets SNMP agent common configuration for v2 and v3 in database.

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: SNMP agent configuration

        """
        ret_val = {
            'status': -1,
            'message': '--'
        }
        response.status = 400
        port = request.json.get('port', SNMP_DEFAULT_PORT)
        contact = request.json.get('contact', '')
        location = request.json.get('location', '')

        if not port:
            ret_val['message'] = 'Port is required.'
            return ret_val

        if port in Consts.ACTIVE_PORTS_LIST:
            ret_val['message'] = 'Port already in use.'
            return ret_val

        config = {
            'port': int(port),
            'contact': contact,
            'location': location,
        }

        try:
            if self.snmp_v2c_config.is_enabled() or self.snmp_v3_config.is_enabled():
                if config.get('port') != self.snmp_dict.get('port'):
                    self.logger.info('Port has changed. Restart SNMP service.')
                    ProcessHandler.restart(port)
        except (IOError, OSError, TypeError):
            self.logger.error("Unable to set SNMP configuration. {}".format(traceback.format_exc()))
            ret_val['message'] = 'Unable to set SNMP configuration.'
            return ret_val
        self.burnside_db.snmp.update({}, {"$set": config}, upsert=True)
        self.snmp_dict.update(config)
        ret_val['message'] = 'SNMP config is updated'
        ret_val['status'] = 0
        ret_val['data'] = config
        response.status = 200
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def setSnmpV2Configuration(self):
        """
        .. http:post:: /sys/20141030/setSnmpAgentConfiguration

            Sets SNMP agent configuration to db. Accepts community string and/or managers

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: SNMP agent configuration for v2c

        """
        ret_val = {
            'status': -1,
            'message': '--'
        }
        response.status = 400
        config = {}
        input_data = request.json

        community_string = input_data.get('community_string')
        managers = input_data.get('managers')

        if community_string is None and managers is None:
            ret_val['message'] = 'Neither community string or managers specified.'
            return ret_val

        if community_string is not None:
            if not community_string:  # To handle the empty string passed
                ret_val['message'] = 'Community string can not be empty.'
                return ret_val
            result = validate_community_string(community_string)
            if not result:
                ret_val['message'] = 'Invalid community string {}. Cannot contain single quotes({}).'.format(
                    community_string, "'")
                return ret_val
            config['community_string'] = community_string
            config['hash_revision'] = HASH_REVISION_2

        if managers is not None:
            if not isinstance(managers, list):
                ret_val['message'] = 'Managers values are not properly formatted.'
                return ret_val
            config['managers'] = get_unique_managers(managers)

        try:
            if self.snmp_v2c_config.is_enabled():
                if (config.get('community_string') and
                        config.get('community_string') != self.snmp_dict.get('community_string')):
                    self.logger.info('Community string or port has changed. Restart SNMP service.')
                    port = self.snmp_dict.get('port', SNMP_DEFAULT_PORT)
                    self._enable_snmp(SNMP_VERSION_V2C, port, config)
        except (IOError, OSError, TypeError):
            self.logger.error("Unable to set SNMP configuration. {}".format(traceback.format_exc()))
            ret_val['message'] = 'Unable to set SNMP configuration.'
            return ret_val

        self.burnside_db.snmp.update({}, {"$set": encode_configuration(config)}, upsert=True)
        self.snmp_dict.update(decode_configuration(config))
        ret_val['message'] = 'SNMP config is updated'
        ret_val['status'] = 0
        ret_val['data'] = {k: self.snmp_dict.get(k) for k in ['community_string', 'managers', 'hash_revision']}
        response.status = 200
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def setSnmpV3Managers(self):
        """
        .. http:post:: /sys/20141030/setSnmpV3Managers

            Sets SNMP agent v3 managers to db

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: SNMP agent configuration

        """
        ret_val = {
            'status': -1,
            'message': '--'
        }
        response.status = 400
        try:
            data = request.json
            managers = data.get('v3_managers', [])
            local_managers = self.snmp_dict.get('v3_managers', [])

            # Check managers limit only for add operation
            if managers and len(managers) >= len(local_managers):
                if len(managers) > SNMP_MAX_V3_MANAGERS:
                    ret_val['message'] = 'Maximum v3 managers({}) limit reached. Cleanup managers to ' \
                                         'proceed.'.format(SNMP_MAX_V3_MANAGERS)
                    return ret_val

                securities = self.snmp_dict.get('v3_securities', [])
                found = False
                if securities:
                    for manager in managers:
                        for security in securities:
                            if manager.get('security_name') == security.get('name'):
                                found = True
                if not found:
                    ret_val['message'] = 'Security does not exist. Define security.'
                    return ret_val
                data['v3_managers'] = get_unique_managers(managers)
            self.burnside_db.snmp.update({}, {"$set": data}, upsert=True)
            self.snmp_dict['v3_managers'] = data['v3_managers']
        except (ValueError, AttributeError, TypeError):
            self.logger.error("Unable to set SNMP V3 configuration. {}".format(traceback.format_exc()))
            ret_val['message'] = 'Unable to set SNMP V3 configuration.'
            return ret_val
        ret_val['message'] = 'SNMP config is updated'
        ret_val['status'] = 0
        ret_val['data'] = data
        response.status = 200
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def addSnmpV3Security(self):
        """
        .. http:post:: /sys/20141030/addSnmpV3Security

            Add SNMP v3 security to DB

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: SNMP agent configuration

        """
        ret_val = {'status': -1, 'message': '--'}
        securities = self.snmp_dict.get('v3_securities', [])
        port = self.snmp_dict.get('port', SNMP_DEFAULT_PORT)
        response.status = 400
        try:
            data = request.json
            if len(securities) == SNMP_MAX_V3_SECURITIES:
                ret_val['message'] = 'Maximum securities({}) limit reached. Cleanup securities to proceed.'.format(
                    SNMP_MAX_V3_SECURITIES)
                return ret_val

            error_list = validate_security(data, securities)
            self.logger.info("Error list : {}".format(error_list))
            if error_list:
                ret_val["message"] = ', '.join(error_list)
                return ret_val

            securities.append(data)
            if self.snmp_v3_config.is_enabled():
                set_snmp_v3_config(securities=securities, logger=self.logger,
                                   interface_name=self.ubCfg.GetManagementInterfaceName())
                ProcessHandler.restart(port)

            doc = {'v3_securities': securities}
            self.burnside_db.snmp.update({}, {'$set': encode_configuration(doc)}, upsert=True)
            self.snmp_dict.update(decode_configuration(doc))
            ret_val['message'] = 'Security is updated'
            ret_val['status'] = 0
            ret_val['data'] = doc
            response.status = 200
        except (ValueError, AttributeError, IOError, OSError):
            self.logger.error('Add security failed {}'.format(traceback.format_exc()))
            ret_val["message"] = "Add security failed."
        return ret_val

    def delete_security(self, security_name, securities):
        port = self.snmp_dict.get('port', SNMP_DEFAULT_PORT)
        # Add default authPriv user for deleting other users
        self.logger.info('Stopping SNMP service...')
        interface_name = self.ubCfg.GetManagementInterfaceName()
        ProcessHandler.stop(self.logger)
        set_snmp_v3_config(securities=self.snmp_dict.get('v3_securities', []), delete=True, logger=self.logger,
                           interface_name=interface_name)
        self.logger.info('Restarting SNMP service...')
        ProcessHandler.restart(port)
        delete_security(security_name, port, logger=self.logger)
        delete_security(SNMP_DEFAULT_USERNAME, port, logger=self.logger)
        self.logger.info('Stopping SNMP service...')
        ProcessHandler.stop(self.logger)
        set_snmp_v3_config(securities=securities, logger=self.logger, interface_name=interface_name)
        self.logger.info('Restarting SNMP service...')
        ProcessHandler.restart(port)

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def editSnmpV3Security(self):
        """
        .. http:post:: /sys/20141030/editSnmpV3Security

            Sets SNMP agent v3 managers to db

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: SNMP agent configuration

        """
        ret_val = {'status': -1, 'message': '--'}
        response.status = 400
        try:
            data = request.json
            old_name = data.pop('old_name', None)
            securities = copy.copy(self.snmp_dict.get('v3_securities', []))
            if len(securities) > SNMP_MAX_V3_SECURITIES:
                ret_val['message'] = 'Maximum securities({}) limit reached. Cleanup securities to proceed.'.format(
                    SNMP_MAX_V3_SECURITIES)
                return ret_val
            new_name = data.get('name')

            if not old_name:
                ret_val['message'] = 'Old security name is required.'
                return ret_val

            error_list = validate_security(data, securities, old_name=old_name)
            if error_list:
                ret_val["message"] = ', '.join(error_list)
                return ret_val

            managers = self.snmp_dict.get('v3_managers', [])
            if old_name != new_name:
                for manager in managers:
                    if old_name == manager.get('security_name'):
                        manager['security_name'] = new_name

            edited = False
            for index, security in enumerate(securities):
                if old_name == security['name']:
                    securities[index] = data
                    edited = True
                    break
            if not edited:
                ret_val['message'] = 'Edit security failed.'
                return ret_val

            if self.snmp_v3_config.is_enabled():
                self.delete_security(old_name, securities)

            doc = {'v3_managers': managers, 'v3_securities': securities}
            self.burnside_db.snmp.update({}, {'$set': encode_configuration(doc)}, upsert=True)
            self.snmp_dict.update(decode_configuration(doc))
            ret_val['status'] = 0
            ret_val['data'] = doc
            ret_val['message'] = "Security updated successfully."
            response.status = 200
        except (ValueError, AttributeError, IOError, OSError):
            self.logger.error('Edit security failed {}'.format(traceback.format_exc()))
            ret_val['message'] = 'Edit security failed.'
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def deleteSnmpV3Security(self):
        """Delete security

        :returns Response stating success/failure
        """
        ret_val = {'status': -1, 'message': '--'}
        response.status = 400
        try:
            security_name = request.json.get('security_name')
            if security_name:
                managers = self.snmp_dict.get('v3_managers', [])
                for manager in managers:
                    if manager.get('security_name') == security_name:
                        ret_val['message'] = 'Unable to delete. Security is used in manager.'
                        return ret_val

                securities = copy.copy(self.snmp_dict.get('v3_securities', []))
                found = False
                for security in securities:
                    if security.get('name') == security_name:
                        found = True
                        securities.remove(security)
                        if self.snmp_v3_config.is_enabled():
                            self.delete_security(security_name, securities)

                        doc = {'v3_securities': securities}
                        self.burnside_db.snmp.update({}, {'$set': encode_configuration(doc)}, upsert=True)
                        self.snmp_dict.update(decode_configuration(doc))
                        ret_val['status'] = 0
                        ret_val['data'] = doc
                        ret_val['message'] = "Security deleted successfully."
                        response.status = 200
                if not found:
                    ret_val['message'] = 'Security does not exist.'
            else:
                ret_val['message'] = 'Delete security failed.'
        except (ValueError, AttributeError, IOError, OSError):
            self.logger.error('Delete security failed {}'.format(traceback.format_exc()))
            ret_val['message'] = 'Delete security failed.'
        return ret_val

    @cp_auth([settings.ADMIN_ROLE, settings.READONLY_ROLE], 'Need admin/read-only access to perform this operation.')
    def downloadSnmpMib(self):
        """
        .. http:get:: /sys/20141030/downloadSnmpMib

            Download SNMP MIB

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: SNMP MIB file

        """
        return bottle.static_file(MIB_FILE_NAME, root=MIB_FILE_PATH, download=MIB_FILE_NAME)

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def getSnmpAgentState(self):
        """
        .. http:get:: /sys/20141030/getSnmpAgentState

            Retrieves SNMP agent state enable/disable

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: SNMP agent state

        """
        ret_val = {
            'status': -1,
            'enabled': None
        }
        self.logger.info('getSnmpAgentState(): START')
        try:
            ret_val['status'] = 0
            ret_val['enabled'] = self.snmp_v2c_config.is_enabled()
        except (IOError, OSError, TypeError):
            self.logger.error('getSnmpAgentState(): Exception: {}'.format(traceback.format_exc()))
            ret_val['message'] = 'Failed to retrieve snmp v2c status'
            response.status = 400
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def setSnmpAgentState(self):
        """
        .. http:post:: /sys/20141030/setSnmpAgentState

            Sets SNMP agent state enable/disable

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: SNMP agent state

        """
        self.logger.info('setSnmpAgentState() : START')
        ret_val = {
            'status': -1,
            'message': '--',
            'enabled': None
        }
        response.status = 400
        if request.content_type.find('json') > -1:  # application/json;charset=utf-8
            snmp_enabled = request.json.get('enabled', None)
        else:
            ret_val['message'] = 'Invalid content-type \'' + request.content_type + '\''
            self.logger.error(ret_val['message'])
            return ret_val

        snmp_status = self.snmp_v2c_config.is_enabled()
        port = self.snmp_dict.get('port', SNMP_DEFAULT_PORT)

        try:
            if snmp_enabled is None:
                ret_val['message'] = 'Invalid SNMP state value'
                return ret_val
            elif snmp_enabled:
                if snmp_status == snmp_enabled:
                    ret_val['message'] = 'SNMP v2c service is enabled'
                    ret_val['enabled'] = snmp_enabled
                    ret_val['status'] = 0
                else:
                    config = {'community_string': self.snmp_dict.get('community_string',
                                                                     SNMP_DEFAULT_COMMUNITY_STRING)}
                    result = self._enable_snmp(SNMP_VERSION_V2C, port, config)
                    if result:
                        ret_val['message'] = 'SNMP v2c service is enabled'
                        ret_val['enabled'] = snmp_enabled
                        ret_val['status'] = 0
                    else:
                        ret_val['message'] = 'Unable to enable SNMP'
            else:
                if snmp_status == snmp_enabled:
                    ret_val['message'] = 'SNMP v2c service is disabled'
                    ret_val['enabled'] = snmp_enabled
                    ret_val['status'] = 0
                else:
                    result = self._disable_snmp(SNMP_VERSION_V2C, port, config=None)
                    if result:
                        ret_val['message'] = 'SNMP v2c service is disabled'
                        ret_val['enabled'] = snmp_enabled
                        ret_val['status'] = 0
                    else:
                        ret_val['message'] = 'Unable to disable SNMP'
        except (TypeError, AttributeError, ValueError, KeyError):
            self.logger.error('setSnmpAgentState(): Exception: {}'.format(traceback.format_exc()))
            ret_val['message'] = 'Failed to update SNMP v2c state'
        response.status = 200
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def getSnmpV3AgentState(self):
        """
        .. http:get:: /sys/20141030/getSnmpV3AgentState

            Retrieves SNMP V3 agent state enable/disable

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: SNMP V3 agent state

        """
        ret_val = {
            'status': -1,
            'enabled': None
        }
        self.logger.info('getSnmpV3AgentState(): START')
        try:
            ret_val['status'] = 0
            ret_val['enabled'] = self.snmp_v3_config.is_enabled()
        except (IOError, OSError, TypeError):
            self.logger.error('getSnmpV3AgentState(): Exception: {}'.format(traceback.format_exc()))
            ret_val['message'] = 'Failed to retrieve snmp v3 state'
            response.status = 400
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def setSnmpV3AgentState(self):
        """
        .. http:post:: /sys/20141030/setSnmpV3AgentState

            Sets SNMP V3 agent state enable/disable

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: SNMP V3 agent state

        """
        self.logger.info('setSnmpV3AgentState() : START')
        ret_val = {
            'status': -1,
            'message': '--',
            'enabled': None
        }
        response.status = 400
        if request.content_type.find('json') > -1:  # application/json;charset=utf-8
            snmp_enabled = request.json.get('enabled', None)
        else:
            ret_val['message'] = 'Invalid content-type \'' + request.content_type + '\''
            self.logger.error(ret_val['message'])
            return ret_val

        snmp_status = self.snmp_v3_config.is_enabled()
        port = self.snmp_dict.get('port', SNMP_DEFAULT_PORT)
        config = {'v3_securities': self.snmp_dict.get('v3_securities', [])}
        try:
            if snmp_enabled is None:
                ret_val['message'] = 'Invalid SNMP v3 state value'
                return ret_val
            elif snmp_enabled:
                if snmp_status == snmp_enabled:
                    ret_val['message'] = 'SNMP v3 service is enabled'
                    ret_val['enabled'] = snmp_enabled
                    ret_val['status'] = 0
                else:
                    result = self._enable_snmp(SNMP_VERSION_V3, port, config)
                    if result:
                        ret_val['message'] = 'SNMP v3 service is enabled'
                        ret_val['enabled'] = snmp_enabled
                        ret_val['status'] = 0
                    else:
                        ret_val['message'] = 'Unable to enable SNMP'
            else:
                if snmp_status == snmp_enabled:
                    ret_val['message'] = 'SNMP v3 service is disabled'
                    ret_val['enabled'] = snmp_enabled
                    ret_val['status'] = 0
                else:
                    result = self._disable_snmp(SNMP_VERSION_V3, port, config)
                    if result:
                        ret_val['message'] = 'SNMP v3 service is disabled'
                        ret_val['enabled'] = snmp_enabled
                        ret_val['status'] = 0
                    else:
                        ret_val['message'] = 'Unable to disable SNMP'
        except (TypeError, AttributeError, ValueError, KeyError):
            self.logger.error('setSnmpV3AgentState(): Exception: {}'.format(traceback.format_exc()))
            ret_val['message'] = 'Failed to update SNMP v3 state'
        response.status = 200
        return ret_val

    def _update_traps_list(self, trap_info):
        """Update traps list with the latest trap details

        :param trap_info: Trap details to be added to traps list
        """
        with system_lock:
            local_trap_info = {
                'time_of_trap': time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                'trap': trap_info
            }
            self.traps_list.append(local_trap_info)
            if len(self.traps_list) > MAX_TRAP_LIST_SIZE:
                self.traps_list.pop(0)

    def _dispatch_trap(self, manager, port, trap_id, trap_info):
        """Crete trap objects command and call send trap utility

        :param manager: Manager ip
        :param port: Port configured to send the trap
        :param trap_id: Internal trap id
        :param trap_info: Trap details to be sent

        :returns Status and message showing success/failure
        """
        ret_val = {
            'status': -1,
            'message': '--'
        }

        try:
            self.logger.info("Send Trap: Manager: {}:{}.  Trap : {}".format(manager, port, trap_info))
            trap_command = list()
            trap_command.append('CPACKET-CSTOR-MIB::{}'.format(TRAP_ID_MAP.get(trap_id)))
            trap_command = trap_command + create_trap_command(trap_info, NOTIFICATIONS[trap_id])
            community_string = self.snmp_dict.get('community_string', SNMP_DEFAULT_COMMUNITY_STRING)
            self.snmp_v2c_config.send_v2c_trap(manager, port, community_string, trap_command)
        except (OSError, IOError, TypeError, ValueError, AttributeError):
            self.logger.error('Exception while creating the command for trap. {}'.format(traceback.format_exc()))
            ret_val['message'] = 'Unable to send the trap to manager : {}'.format(manager)
            return ret_val
        ret_val['status'] = 0
        ret_val['message'] = 'Dispatched trap'
        return ret_val

    def _send_v2c_trap(self, trap_command):
        """Crete trap objects command and call send trap utility

        :param trap_command: Generated trap command
        :returns Status and message showing success/failure
        """
        ret_val = {'message': '--', 'status': -1}
        for manager in self.snmp_dict.get('managers', []):
            ip = manager.get('ip')
            port = str(manager.get('port'))
            try:
                community_string = self.snmp_dict.get('community_string', SNMP_DEFAULT_COMMUNITY_STRING)
                self.logger.info('Sending V2C trap to manager : {}:{}'.format(ip, port))
                self.snmp_v2c_config.send_v2c_trap(ip, port, community_string, trap_command)
                ret_val['message'] = 'Dispatched trap'
                ret_val['status'] = 0
            except (AttributeError, ValueError, TypeError, OSError, IOError):
                self.logger.error('Exception while creating the command for trap {}'.format(traceback.format_exc()))
                ret_val['message'] = 'Unable to send the trap to manager : {}'.format(manager)
                return ret_val
        return ret_val

    def _send_v3_trap(self, trap_command):
        """Send snmp v3 trap utility

        :param trap_command: Generated trap command
        :returns Status and message showing success/failure
        """
        ret_val = {'message': '', 'status': -1}
        response.status = 400

        securities = self.snmp_dict.get('v3_securities', [])
        if not securities:
            ret_val['message'] = 'No securities exist.'
            return ret_val

        for manager in self.snmp_dict.get('v3_managers', []):
            ip = manager.get('ip')
            port = manager.get('port')
            security_name = manager.get('security_name')
            try:
                security = None
                for value in securities:
                    if value['name'] == security_name:
                        security = value
                        self.logger.info('Sending V3 trap to manager : {}:{}'.format(ip, port))
                        if self.engine_id:
                            engine_id = self.engine_id
                        else:
                            engine_id = SECURITY_ENGINE_MAC_ADDR_FORMAT.format(
                                mac=self.ubCfg.GetNetworkConfiguration(self.ubCfg.GetManagementInterfaceName()
                                                                       ).get('Hwaddr', '')).replace(":", "").upper()
                            self.engine_id = engine_id
                        self.snmp_v3_config.send_v3_trap(ip, port, security, trap_command, engine_id)
                        break
                if not security:
                    self.logger.warn('Security associated with manager not found. {}.'.format(ip))
            except (AttributeError, ValueError, TypeError):
                self.logger.error('Exception while creating the command for trap {}'.format(traceback.format_exc()))
                ret_val['message'] = 'Unable to send the trap to manager : {}'.format(ip)
                return ret_val
        ret_val['message'] = 'Dispatched trap.'
        response.status = 200
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def sendSnmpTrap(self):
        """Utility function to send trap

        :returns Status and message showing success/failure
        """
        self.logger.info('sendSnmpTrap(): START')
        ret_val = {'message': '', 'status': -1}
        response.status = 400

        if request.content_type.find('json') > -1:  # application/json;charset=utf-8
            trap_info = request.json
        else:
            ret_val['message'] = 'Invalid content-type {}'.format(request.content_type)
            self.logger.error(ret_val['message'])
            return ret_val

        if not (self.snmp_v2c_config.is_enabled() or self.snmp_v3_config.is_enabled()):
            ret_val['message'] = "SNMP agent is not enabled."
            self.logger.error(ret_val['message'])
            return ret_val

        manager_exists = False
        if self.snmp_v2c_config.is_enabled() and self.snmp_dict.get('managers', []):
            manager_exists = True

        if self.snmp_v3_config.is_enabled() and self.snmp_dict.get('v3_managers', []):
            manager_exists = True

        if not manager_exists:
            ret_val['message'] = "There are no SNMP managers configured"
            self.logger.error(ret_val['message'])
            return ret_val

        # Validate trap_info for its format
        result = validate_trap_info(trap_info, logger=self.logger)
        if result['status'] != 0:
            self.logger.error('Unable to validate the traps info.')
            return result

        if 'internal_trap_id' not in trap_info:
            ret_val['message'] = "No Trap id provided"
            self.logger.error(ret_val['message'])
            return ret_val

        self._update_traps_list(trap_info)
        trap_id = trap_info.pop('internal_trap_id', None)
        trap_command = []
        trap_command.append('CPACKET-CSTOR-MIB::{}'.format(TRAP_ID_MAP.get(trap_id)))
        trap_command = trap_command + create_trap_command(trap_info, NOTIFICATIONS[trap_id])
        result_v2c = None
        if self.snmp_v2c_config.is_enabled() and self.snmp_dict.get('managers', []):
            result_v2c = self._send_v2c_trap(trap_command)

        result_v3 = None
        if self.snmp_v3_config.is_enabled() and self.snmp_dict.get('v3_managers', []):
            result_v3 = self._send_v3_trap(trap_command)

        status = 0
        if result_v2c:
            if result_v2c['status'] == -1:
                ret_val['message'] = result_v2c['message']
                status = -1
        else:
            ret_val['message'] = 'No SNMP v2c managers configured.'
            status = -1

        if result_v3:
            if result_v3['status'] == -1:
                ret_val['message'] += ' {}'.format(result_v3['message'])
                status = -1
        else:
            ret_val['message'] += ' No SNMP v3 managers configured.'
            status = -1
        ret_val['message'] = ret_val['message'].strip()
        if status == -1:
            return ret_val

        self.logger.debug("Successfully dispatched the trap.")
        ret_val['status'] = 0
        ret_val['message'] = 'Successfully dispatched the trap.'
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def sendSampleSnmpTrap(self):
        """Utility function to send sample trap for testing managers

        :returns Status and message showing success/failure
        """
        notification_type = None
        version = None
        result = None
        ret_val = {'message': 'Unable to send SNMP trap.', 'status': -1}
        response.status = 400
        try:
            if request.method == 'GET':
                result = request.query
            elif request.method == 'POST':
                result = request.json
        except (AttributeError, ValueError):
            self.logger.error('No request data. Generate all traps for v2c and v3 {}'.format(traceback.format_exc()))

        if result:
            version = result.get('version')
            notification_type = result.get('type')

        if version and version not in [SNMP_VERSION_V2C, SNMP_VERSION_V3]:
            ret_val['message'] = 'Invalid version type. Version needs to be v2c/v3'
            return ret_val

        notifications_list = []
        if notification_type:
            if notification_type.lower() not in list(SAMPLE_TRAP_OBJECTS.keys()):
                ret_val['message'] = 'Invalid notification type. Type needs to be {}'.format(str(list(
                    SAMPLE_TRAP_OBJECTS.keys())))
                return ret_val
            else:
                notifications_list.append(notification_type.lower())
        else:
            notifications_list = list(SAMPLE_TRAP_OBJECTS.keys())

        self.logger.info('Notifications : {}'.format(notifications_list))
        try:
            for item in notifications_list:
                trap_info = copy.deepcopy(SAMPLE_TRAP_OBJECTS.get(item))
                trap_id = trap_info.pop('internal_trap_id', None)
                trap_command = []
                trap_command.append('CPACKET-CSTOR-MIB::{}'.format(TRAP_ID_MAP.get(trap_id)))
                trap_command = trap_command + create_trap_command(trap_info, NOTIFICATIONS[trap_id])
                if version:
                    if (
                            version == SNMP_VERSION_V2C
                            and self.snmp_v2c_config.is_enabled()
                            and self.snmp_dict.get('managers', [])
                    ):
                        self._send_v2c_trap(trap_command)
                    elif (
                            version == SNMP_VERSION_V3
                            and self.snmp_v3_config.is_enabled()
                            and self.snmp_dict.get('v3_managers', [])
                    ):
                        self._send_v3_trap(trap_command)
                else:
                    if self.snmp_v2c_config.is_enabled() and self.snmp_dict.get('managers', []):
                        self._send_v2c_trap(trap_command)
                    if self.snmp_v3_config.is_enabled() and self.snmp_dict.get('v3_managers', []):
                        self._send_v3_trap(trap_command)
        except (ValueError, TypeError, AttributeError, KeyError):
            self.logger.error('Unable to generate trap. {}'.format(traceback.format_exc()))
            return ret_val
        ret_val['message'] = 'Successfully sent the sample trap(s).'
        ret_val['status'] = 0
        response.status = 200
        return ret_val

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def mountDrive(self):
        """
        .. http:post:: /sys/20141030/mountDrive

            mounts a drive

           :param devPath: the /dev/sd? path of the drive
           :param label: the label to use for the new hard-drive. if the label is None use the label on the drive
           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: HTTP error code

        """
        (dev_path, status, error) = extract_parameter('devPath', param_type=ParameterType.string)
        if not dev_path:
            raise bottle.HTTPResponse(status=status, body=error)
        (label, status, error) = extract_parameter('label', param_type=ParameterType.string)
        if not label:
            raise bottle.HTTPResponse(status=status, body=error)
        self._halt_main_services()
        dw = driveWrapper(self.logger, self.burnside_db, dev_path)
        dw.cleaning = True
        self.logger.debug("Mounting drive: {}".format(dw.path))
        rv = dw.mount_me(label)
        dw.cleaning = False
        # now that all the other processes are running - exit with a non-zero and let upstart restart the process
        self._exit_process()

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def umountDrive(self):
        """
        .. http:post:: /sys/20141030/umountDrive

            unmount a drive

           :param path: the media DATA path of the drive to unmount
           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        (path, status, error) = extract_parameter('path', param_type=ParameterType.string)
        if not path:
            raise bottle.HTTPResponse(status=status, body=error)
        dw = driveWrapper(self.logger, self.burnside_db, path)
        dw.cleaning = True
        self.logger.debug("Unmounting drive: {}".format(dw.path))
        rv = dw.umount_me()
        dw.cleaning = False
        if rv != 0:
            raise bottle.HTTPResponse(status=500, body="failed to un-mount drive - stop traffic flow")

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def blinkDrive(self):
        """
        .. http:post:: /sys/20141030/blinkDrive

            blink the drive light

           :param path: the media DATA path of the drive to unmount
           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        (path, status, error) = extract_parameter('path', param_type=ParameterType.string)
        if not path:
            raise bottle.HTTPResponse(status=status, body=error)
        d = self.burnside_db.drives.find({'fs_path' : path})
        if d.count == 0:
            raise bottle.HTTPResponse(status=400, body="Invalid path for drive")

        dw = driveWrapper(self.logger, self.burnside_db, path)
        dw.cleaning = True
        self.logger.debug("Blinking drive: {}".format(dw.path))
        rv = dw.blink_me()
        dw.cleaning = False
        if rv != 0:
            raise bottle.HTTPResponse(status=500, body="failed to un-mount drive - stop traffic flow")

    @cp_auth([settings.ADMIN_ROLE], 'Need admin access to perform this operation.')
    def bindNic2Dpdk(self):
        """
        .. http:post:: /sys/20141030/attachNic2Dpdk
            Bind a NIC to DPDK
           :param captureNicIndex: the NIC to bind to dpdk
           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return: HTTP error code

        """
        capture_nic_index = extract_parameter('captureNicIndex', param_type=ParameterType.int)
        self._update_sys_setting_in_db('capture_nic_index', capture_nic_index)
        rc, num_nics = init_dpdk_nics(capture_nic_index)
        self._update_sys_setting_in_db('num_nics', num_nics)
        if rc is not None:
            self.logger.debug("Bind NIC {} ({}) to DPDK successful".format(capture_nic_index, rc))
            control_process('cleanup', 'restart')
        else:
            self.logger.debug("Bind NIC {} failed".format(capture_nic_index))
        return {'status': 'success'}

    def getCProbeConfig(self):
        cprobe = cProbeControl(self.burnside_db, self.logger)
        try:
            config = cprobe.get_configuration()
        except Exception as e:
            self.logger.error("Failed to get cprobe configuration - {}".format(str(e)))
            traceback.print_stack(limit=6)
            config = {'status': 'failed to read cprobe configuration'}
        return json.dumps(config)

    def lockCProbe(self):
        cprobe = cProbeControl(self.burnside_db, self.logger)
        return cprobe.lock(True)

    def unlockCProbe(self):
        cprobe = cProbeControl(self.burnside_db, self.logger)
        return cprobe.lock(False)

    def initQSFPMode(self):
        """
            Internal function to read the current QSFP mode and save it in DB
        """
        try:
            mode_curr = Consts.QSFP_MODE_UNSUPPORTED
            capture_mode = self.burnside_db.system_settings.find_one({}, {"_id": False, "capture_mode": True})
            # read the current qsfp mode configured on the device
            if capture_mode and capture_mode.get('capture_mode') == 'cprobe':
                cprobe = cProbeControl(self.burnside_db, self.logger)
                if cprobe.detect_compatible_adapter():
                    mode_curr = cprobe.get_qsfp_mode()
            # read the qsfp mode saved in the database
            qsfp_mode = self.burnside_db.system_settings.find_one({}, {'_id': False, 'qsfp_mode': True})
            mode_saved = qsfp_mode.get("qsfp_mode")
            if mode_curr != mode_saved:
                self.logger.debug("Overwriting qsfp_mode in db:{} with current mode:{}".format(mode_saved, mode_curr))
                self.burnside_db.system_settings.update_one({}, {"$set": {'qsfp_mode': mode_curr}})
                if mode_curr in Consts.QSFP_MODES_SUPPORTED:
                    if self.ubCfg.switch_traffic_interfaces(mode_curr):
                        self.logger.debug("switched netplan configuration")
                    else:
                        msg = "Failed to apply network configuration for qsfp_mode: %s" % mode_curr
                        self.logger.error(msg)
        except Exception as e:
            self.logger.error("Failed to initialize qsfp_mode - {}".format(str(e)))
            traceback.print_stack(limit=6)

    def initMTUSize(self):
        """
            Function to set MTU Size on the traffic interfaces
        """
        try:
            capture_mode = self.burnside_db.system_settings.find_one({}, {"_id": False, "capture_mode": True})
            # read the current qsfp mode configured on the device
            mtu_flag = False
            if capture_mode and capture_mode.get('capture_mode') == 'cprobe':
                cprobe = cProbeControl(self.burnside_db, self.logger)
                if cprobe.detect_compatible_adapter():
                    mtu_flag = True
            if mtu_flag:
                # read the mtu size saved in the database
                interface_info = self.burnside_db.system_settings.find_one({}, {'_id': False, 'mtu_size': True,
                                                                                'qsfp_mode': True})
                mtu_size = int(interface_info.get('mtu_size', Consts.MTU_SIZE_JUMBO))
                qsfp_mode = interface_info.get('qsfp_mode')
                if mtu_size < Consts.MTU_SIZE_MIN or mtu_size > Consts.MTU_SIZE_MAX:
                    self.logger.debug("Invalid mtu_size:{}, override with {}".format(mtu_size, Consts.MTU_SIZE_JUMBO))
                    mtu_size = Consts.MTU_SIZE_JUMBO
                r, msg = self.ubCfg.set_traffic_interfaces_mtu_size(mtu_size, qsfp_mode)
                self.logger.debug(msg)
            else:
                self.logger.debug("Not setting MTU size")
        except Exception as e:
            self.logger.error("Failed to set MTU size {}".format(str(e)))

    def getQSFPMode(self):
        """
           http:get:: /sys/20141030/getQSFPMode
           Returns the QSFP mode and supported queues
        """
        bottle.response.headers['Content-Type'] = 'application/json'
        resp = {"qsfp_mode": Consts.QSFP_MODE_UNSUPPORTED}
        try:
            config = self.burnside_db.system_settings.find_one({}, {
                '_id': False,
                'qsfp_mode': True,
                'cprobe_num_queues_sw': True,
                'cprobe_num_queues_hw': True
            })
            if config.get('qsfp_mode') == Consts.QSFP_MODE_2x40:
                resp['qsfp_mode'] = config['qsfp_mode']
                resp['software_balancer_supported'] = True
                resp['hardware_queues_supported'] = Consts.CPROBE_NUM_QUEUES_HW_SUPPORTED
                resp['software_queues_supported'] = Consts.CPROBE_NUM_QUEUES_SW_SUPPORTED
            elif config.get('qsfp_mode') == Consts.QSFP_MODE_4x10:
                resp['qsfp_mode'] = config['qsfp_mode']
                resp['software_balancer_supported'] = False
                resp['hardware_queues_supported'] = Consts.CPROBE_NUM_QUEUES_HW_SUPPORTED
            # else myricom cards do not support switching qsfp modes
        except Exception as e:
            self.logger.error("Failed to get qsfp_mode - {}".format(str(e)))
        return resp

    def _setQSFPMode(self, cprobe, mode):
        """
            Internal function to set the QSFP mode
        """
        status = False
        msg = "Unknown error"
        try:
            self.logger.debug("Setting qsfp_mode:{}".format(mode))
            status, msg = cprobe.set_qsfp_mode(mode)
            if status:
                self.burnside_db.system_settings.update_one({}, {"$set": {'qsfp_mode': mode}})
                if not self.ubCfg.switch_traffic_interfaces(mode):
                    msg = "Failed to apply network configuration for qsfp_mode: %s" % mode
                    self.logger.error(msg)
                    status = False
        except Exception as e:
            self.logger.error("Failed to set qsfp_mode to: {} - {}".format(mode, e))
            traceback.print_stack(limit=6)
        return status, msg

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to change qsfp mode')
    def setQSFPMode(self):
        """
        .. http:post:: /sys/20141030/setQSFPMode
            Sets the QSFP mode
        """
        bottle.response.headers['Content-Type'] = 'application/json'
        cprobe = cProbeControl(self.burnside_db, self.logger)
        if not cprobe.detect_compatible_adapter():
            error_msg = 'Unsupported operation, no compatible adapters available'
            raise bottle.HTTPResponse(status=400, body=error_msg)
        retval = {}
        if request.json:
            mode = request.json.get('qsfp_mode', None)
        else:
            mode = None
        if mode and mode in Consts.QSFP_MODES_SUPPORTED:
            status, msg = self._setQSFPMode(cprobe, mode)
        else:
            status = False
            msg = 'Expected valid QSFP mode, supported modes: %s' % str(Consts.QSFP_MODES_SUPPORTED)
        retval['status'] = status
        retval['message'] = msg
        # send back the set value to UI
        retval['config'] = self.getQSFPMode()
        return retval

    def setQSFPModeFromDB(self):
        """
        Set QSFP mode from the value saved in the database.
        This routine is supposed to be called only from the restore path.
        """

        # Take a backup of the balancer state. Software balancer state is influenced by
        # the current running qsfp mode. If the system is running in qsfp 4x10 mode,
        # this value is force set to 'False' (in 'cProbeControl()'). If that happens,
        # restore it so that the system boots up with the desired configuration.
        enable_balancer_dict = self.burnside_db.system_settings.find_one({}, {'_id': False, 'cprobe_enable_balancer': True})
        enable_balancer = enable_balancer_dict.get('cprobe_enable_balancer', False)
        cprobe = cProbeControl(self.burnside_db, self.logger)
        try:
            qsfp_mode = self.burnside_db.system_settings.find_one({}, {'_id': False, 'qsfp_mode': True})
            mode = qsfp_mode.get("qsfp_mode")
            self.logger.debug("Restoring QSFP mode to: {}".format(mode))
            if mode in Consts.QSFP_MODES_SUPPORTED:
                if not cprobe.detect_compatible_adapter():
                    self.burnside_db.system_settings.update_one({}, {"$set": {'qsfp_mode': Consts.QSFP_MODE_UNSUPPORTED}})
                    return
                self._setQSFPMode(cprobe, mode)
            elif mode == Consts.QSFP_MODE_UNSUPPORTED:
                self.logger.debug("qsfp_mode in db: {}".format(mode))
            else:
                self.logger.error("Invalid qsfp_mode in db: {}".format(mode))
            # Restore the original rss state
            self.burnside_db.system_settings.update_one({}, {"$set": {'cprobe_enable_balancer': enable_balancer}})
        except Exception as e:
            self.logger.error("Failed to restore qsfp_mode - {}".format(str(e)))
            traceback.print_stack(limit=6)

    def getRSSConfig(self):
        """
        .. http:get:: /sys/20141030/getRSSConfig
            Gets the RSS configuration
        """
        bottle.response.headers['Content-Type'] = 'application/json'
        rss_config = {'cprobe_enable_balancer': True,
                      'cprobe_num_queues_hw': Consts.CPROBE_NUM_QUEUES_HW,
                      'cprobe_num_queues_sw': Consts.CPROBE_NUM_QUEUES_SW}
        try:
            rss_config = self.burnside_db.system_settings.find_one({}, {'_id': False,
                                                                        'cprobe_enable_balancer': True,
                                                                        'cprobe_num_queues_hw': True,
                                                                        'cprobe_num_queues_sw': True})
        except Exception as e:
            self.logger.error("Failed to get RSS configuration {}".format(e))
        return rss_config

    @cp_auth('admin', 'Have to be an admin to change RSS configuration')
    def setRSSConfig(self):
        """
        .. http:post:: /sys/20141030/setRSSConfig
            Sets the RSS configuration
        """
        bottle.response.headers['Content-Type'] = 'application/json'
        try:
            cprobe = cProbeControl(self.burnside_db, self.logger)
            enable_balancer = request.json.get('cprobe_enable_balancer')
            str_num_queues_hw = request.json.get('cprobe_num_queues_hw')
            str_num_queues_sw = request.json.get('cprobe_num_queues_sw')
            if None in [enable_balancer, str_num_queues_hw] and None in [enable_balancer, str_num_queues_sw]:
                self._log_and_abort(400, 'Missing parameters for RSS configuration')
            elif not cprobe.detect_compatible_adapter():
                self._log_and_abort(400, 'Unsupported operation, no compatible adapters available')
            else:
                num_queues_hw = int(str_num_queues_hw) if str_num_queues_hw else 0
                num_queues_sw = int(str_num_queues_sw) if str_num_queues_sw else 0
                if cprobe.get_qsfp_mode() == Consts.QSFP_MODE_4x10 and enable_balancer:
                    self._log_and_abort(400, 'Software distribution is not supported in 4x10 mode')
                elif not enable_balancer and num_queues_hw not in Consts.CPROBE_NUM_QUEUES_HW_SUPPORTED:
                    self._log_and_abort(400, 'Unsupported #queues(hardware), use one of {}'.format(
                                        Consts.CPROBE_NUM_QUEUES_HW_SUPPORTED))
                elif enable_balancer and num_queues_sw not in Consts.CPROBE_NUM_QUEUES_SW_SUPPORTED:
                    self._log_and_abort(400, 'Unsupported #queues(software), use one of {}'.format(
                                        Consts.CPROBE_NUM_QUEUES_SW_SUPPORTED))
                else:
                    # Restrict generic block exception handler to only update database
                    # We do not want generic handler for the whole endpoint since we do not
                    # want to catch the exception thrown by _log_and_abort() instead we want that
                    # to be handled by bottleapp.
                    try:
                        self._update_sys_setting_in_db('cprobe_enable_balancer', enable_balancer)
                        if enable_balancer:
                            self._update_sys_setting_in_db('cprobe_num_queues_sw', num_queues_sw)
                        else:
                            self._update_sys_setting_in_db('cprobe_num_queues_hw', num_queues_hw)
                    except Exception as e:
                        self.logger.error("Failed to set RSS [ updating db failed ] - {}".format(str(e)))
                        self._log_and_abort(500, 'Failed to set RSS configuration')
        except (ValueError, TypeError, KeyError) as e:
            # Handle incomplete / incorrect json request
            self.logger.error("Failed to set RSS [ parse error ] - {}".format(str(e)))
            self._log_and_abort(400, 'Failed to parse json request')

        # Return updated configuration back to UI
        rss_config = self.getRSSConfig()
        self.logger.debug("setRSSConfig:{}".format(json.dumps(rss_config)))
        return {'config': rss_config}

    def _get_bios_info(self):
        bios_commands = [
            ("vendor", "dmidecode --string bios-vendor"),
            ("version", "dmidecode --string bios-version"),
            ("release_date", "dmidecode --string bios-release-date"),
        ]

        bios = {}
        for key, cmd in bios_commands:
            rc, serr, sout = run_cmd("/bin/bash -c '{}'".format(cmd), True)

            if sout is not None or sout != "":
                bios[key] = sout.strip() or "N/A"
            else:
                bios[key] = "N/A"

        return bios

    def _get_board_info(self):
        basebord_commands = [
            ("manufacturer", "dmidecode --string baseboard-manufacturer"),
            ("name", "dmidecode --string baseboard-product-name"),
            ("version", "dmidecode --string baseboard-version"),
            ("serial_number", "dmidecode --string baseboard-serial-number"),
        ]

        motherboard = {}
        for key, cmd in basebord_commands:
            rc, serr, sout = run_cmd("/bin/bash -c '{}'".format(cmd), True)

            if sout is not None or sout != "":
                motherboard[key] = sout.strip() or "N/A"
            else:
                motherboard[key] = "N/A"

        return motherboard

    def getSystemHardwareInfo(self):
        """
        .. http:get:: /sys/20141030/getSystemHardwareInfo
            Gets the System bios/board details
            :statuscode 400: when form invalid info_type is passed
            :statuscode 401: unauthorized to perform the action
            :param info_type: optional, bios, motherboard or all
            :return: Bios and motherboard information

        """
        if request.query:
            info_type = request.query.get('info_type', 'all')
        else:
            info_type = 'all'

        if info_type not in ['all', 'motherboard', 'bios']:
            return self._json_error("Un-supported info_type '{}'".format(info_type), 400)

        result = {}

        if info_type in ['all', 'motherboard']:
            result["motherboard"] = self._get_board_info()

        if info_type in ['all', 'bios']:
            result["bios"] = self._get_bios_info()

        return result

    def getHostname(self):
        """
        .. http:post:: /sys/20141030/getHostname

            Retrieves getHostname

           :statuscode 401: unauthorized to perform the action
           :return hostname:
        """
        return {"hostname" : subprocess.check_output(['hostnamectl', 'status', '--static']).decode().strip()}

    @cp_auth([settings.ADMIN_ROLE], 'Have to be an admin to set the hostname')
    def setHostname(self):
        """
        .. http:post:: /sys/20141030/setHostname

            Sets hostname for the system

           :statuscode 400: when form parameters are missing
           :statuscode 401: unauthorized to perform the action
           :return:
        """
        hostname = extract_parameter('hostname', ParameterType.string).value
        hostname_cmd = "hostnamectl set-hostname {}".format(hostname)

        rc, serr, sout = run_cmd(hostname_cmd, True)

        if rc != 0 or serr != '':
            return {'success': False, 'info': 'Unable to set the hostname {}'.format(hostname)}

        new_hosts = ''
        with open('/etc/hosts', 'r') as f:
            for line in f:
                if line.startswith('127.0.1.1'):
                    new_hosts += '127.0.1.1 {}\n'.format(hostname)
                else:
                    new_hosts += line
        with open('/etc/hosts', 'w') as f:
            f.write(new_hosts)

        return {'success': True, 'info': 'Updated the hostname to {}'.format(hostname)}

    def _init_acl_configuration(self):
        """
        Initialize acl status based on the configuration.
        """
        projection = {'acl.enabled': True, '_id': False}
        acl_status = self.burnside_db.system_settings.find_one({}, projection=projection)
        if acl_status and acl_status.get('acl', {}).get('enabled'):
            self.logger.info("Enable ACL feature during startup")
            self.acl_config.enable()
        else:
            self.logger.info("Disable ACL feature during startup")
            self.acl_config.disable()

    def _get_acl_status(self):
        result = self.acl_config.status()
        return {
            'status': 'success',
            'enabled': result.get('enabled')
        }

    def getAclStatus(self):
        """
            .. http:get:: /sys/20141030/getAclStatus
            Gets the Access Control List status
            :return: dictionary including aclStatus
        """

        return self._get_acl_status()

    @cp_auth([settings.ADMIN_ROLE], 'Admin privileges required.')
    def setAclStatus(self):
        """
            .. http:get:: /sys/20141030/setAclStatus
            Sets the Access Control List status
            :return: dictionary including aclStatus
        """
        ret_val = {
            'status': 'error',
            'message': '--',
            'enabled': None
        }
        response.status = 400
        enable = extract_parameter('enable', ParameterType.bool).value
        if enable is None:
            self._log_and_abort(400, "Missing parameter 'enable'.")

        if enable:
            # ensure you have at least one entry in the whitelist
            acl_list = self.acl_config.get_acl_configuration()
            # Not considering CLUSTER entries for now.
            if len(acl_list[ACL_WHITELIST]) == 0:
                return {
                    'status': 'error',
                    'message': 'The ACL whitelist should have at least one host. ACL status can not be enabled .',
                    'config': self.acl_config.get_acl_configuration()
                }
            self.acl_config.enable()
        else:
            self.acl_config.disable()

        acl_enabled = self._get_acl_status().get('enabled')

        if acl_enabled is None:
            ret_val['message'] = 'Invalid ACL status value'
            return ret_val
        elif acl_enabled != enable:
            ret_val['message'] = 'Failed to set the requested state'
            return ret_val

        ret_val['enabled'] = acl_enabled
        ret_val['status'] = 'success'
        response.status = 200
        if acl_enabled:
            ret_val['message'] = 'ACL is enabled'
        else:
            ret_val['message'] = 'ACL is disabled'

        return ret_val

    def getAccessControlList(self):
        """
        .. http:post:: /sys/20141030/getAccessControlList

            Retrieves getACLStatus

           :statuscode 401: unauthorized to perform the action
           :return ACL Configuration
        """
        return {
            'status': 'success',
            'config': self.acl_config.get_acl_configuration()
        }

    @cp_auth([settings.ADMIN_ROLE], 'Admin privileges required.')
    def setAccessControlList(self):
        """
        .. http:post:: /sys/20141030/setAccessControlList

            Sets the ACL configuration

            :statuscode 400: when form parameters are missing
            :statuscode 401: unauthorized to perform the action
            :return ACL Configuration
        """

        """
        {
            'category': 'whitelist/cluster',
            'members': [{'source': '1.1.1.1'},{'source':'2.2.2.2'}]
             }
        """
        (replace, status, error) = extract_parameter('replace', param_type=ParameterType.bool)
        if not replace:
            replace = False

        response.status = 400
        self.logger.debug("Request for setting access control {}".format(request.json))
        category = request.json.get('category', ACL_WHITELIST)
        if category not in [ACL_CLUSTER, ACL_WHITELIST]:
            return {
                'status': 'error',
                'message': '{} is an invalid category. Valid entries are {}, {}'.
                    format(category, ACL_WHITELIST, ACL_CLUSTER),
                'config': self.acl_config.get_acl_configuration()
            }

        members = request.json.get('members', [])
        # Validate the entries
        for entry in members:
            try:
                if not isinstance(entry, dict):
                    raise ValueError

                # the ip_address without netmask will get /32 appended. This will validate both ip and cidr
                ip_network(unicode(entry['source']), False)
            except (ValueError, KeyError):
                self.logger.info("{}".format(traceback.format_exc()))
                return {
                    'status': 'error',
                    'message': 'Found invalid entry in members. {}'.format(entry),
                    'config': self.acl_config.get_acl_configuration()
                }

        acl_status = self._get_acl_status()

        # Ensure that  you have at least one entry
        if replace and acl_status['enabled'] and len(members) == 0:
            # Use this if you want to ensure both Cluster and whitelist are to be checked
            # acl_list = self.acl_config.get_acl_configuration()
            # if (category == ACL_CLUSTER and len(acl_list[ACL_WHITELIST]) == 0) or \
            #         (category == ACL_WHITELIST and len(acl_list[ACL_CLUSTER]) == 0):
            if category == ACL_WHITELIST:
                return {
                    'status': 'error',
                    'message': 'ACL status is enabled and you cannot delete the only IP in the list.',
                    'config': self.acl_config.get_acl_configuration()
                }

        config = {'category': category, 'members': members}
        result = self.acl_config.set_acl_configuration(config, replace, limit=self.acl_members_limit)
        if result.get('status', 'fail') != "success":
            return {
                'status': 'error',
                'message': result.get('message', "Unknown"),
                'config': self.acl_config.get_acl_configuration()
            }

        # if acl feature was enabled : Disable and enable the acl to reflect the changes.
        if acl_status['enabled']:
            self.acl_config.re_enable()
        response.status = 200
        return {
            'status': 'success',
            'message': 'Updated the Access Control List',
            'config': self.acl_config.get_acl_configuration()
        }

    @cp_auth([settings.ADMIN_ROLE], 'Admin privileges required.')
    def deleteAccessControlList(self):
        """
        .. http:post:: /sys/20141030/deleteAccessControlList

            deletes the ACL configuration

            :statuscode 400: when form parameters are missing
            :statuscode 401: unauthorized to perform the action
            :return ACL Configuration
        """

        """
        {
            'category': 'whitelist/cluster',
            'members': [{'source': '1.1.1.1'},{'source':'2.2.2.2'}]
             }
        """

        response.status = 400
        self.logger.debug("Request for deleting access control {}".format(request.json))
        category = request.json.get('category', ACL_WHITELIST)
        if category not in [ACL_CLUSTER, ACL_WHITELIST]:
            return {
                'status': 'error',
                'message': '{} is an invalid category. Valid entries are {}, {}'.
                    format(category, ACL_WHITELIST, ACL_CLUSTER),
                'config': self.acl_config.get_acl_configuration()
            }
        members = request.json.get('members', [])
        # TODO add validation
        config = {'category': category, 'members': members}
        acl_list = self.acl_config.get_acl_configuration()
        acl_status = self._get_acl_status()
        if acl_status['enabled'] and category == ACL_WHITELIST and len(acl_list[ACL_WHITELIST]) == 1:
            return {
                'status': 'error',
                'message': 'ACL status is enabled and you cannot delete the only IP in the whitelist.',
                'config': self.acl_config.get_acl_configuration()
            }
        else:
            self.acl_config.delete_acl_configuration(config)
            # if acl feature was enabled : Disable and enable the acl to reflect the changes.
            if acl_status['enabled']:
                self.acl_config.re_enable()
            response.status = 200
            return {
                'status': 'success',
                'message': 'Deleted an IP for ACL',
                'config': self.acl_config.get_acl_configuration()
            }


def set_smp_affinity(capture_mode):
    """
    A method to set the smp affinity of myricom driver
    you can watch the interrupts count by calling " watch -n .2 "cat /proc/interrupts"
    we direct all the interrupts for Myricom to CPU-1 so cstor_snf should run there
    """
    if not getattr(sys, 'frozen', False):
        return
    if capture_mode == 'myricom':
        cpu_mask = 2
        my_cmd = "find /proc/irq -name \"myriC0*\""
        p = subprocess.Popen(my_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sout, serr = p.communicate()
        lines = sout.splitlines()
        for l in lines:
            smp_dir = os.path.dirname(l)
            my_cmd = "echo {} >> {}".format(cpu_mask, os.path.join(smp_dir, "smp_affinity"))
            print ("{}".format(my_cmd))
            p = subprocess.Popen(my_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = p.communicate()[0]


def read_num_drives():
    num_drives = 0
    try:
        with open('/etc/fstab', 'r') as version_fd:
            for line in version_fd.readlines():
                if line.startswith('LABEL=DATA_'):
                    num_drives += 1
    except IOError:
        print ("WARNING: could not find /etc/fstab???!!!")
    print ("INFO: number of drives in fstab: {}".format(num_drives))
    return num_drives


def read_factory_config():
    factory_cfg_filename = Consts.INI_FACTORYCONFIG
    if os.path.isfile(factory_cfg_filename):
        factoryinireader = Myappconfig(factory_cfg_filename)
        factory_cfg = {}
        factory_cfg['serialNumber'] = factoryinireader.cfg.get('factory', 'system_sn', '----')
        factory_cfg['platform'] = factoryinireader.cfg.get('factory', 'platform', '----')
        factory_cfg['sku'] = factoryinireader.cfg.get('factory', 'sku', '----')
    else:
        factory_cfg = {'serialNumber': '---', 'platform': '---', 'sku': '---'}
    return factory_cfg


def init_tacacs_settings(db):
    """
    Initializes the tacacs settings collection if it's not there
    :return:
    """
    default_tacacs_settings = {"tacacs_service_name": "",
                               "enabled": False,
                               "servers": []}
    db_tacacs_settings = db.tacacs_settings
    _tacacs_settings = db_tacacs_settings.find_one()
    if _tacacs_settings is None:
        db_tacacs_settings.insert(default_tacacs_settings)
    else:
        # ensure shared secret remains encrypted in the db
        encoded_tacacs_settings = encode_secrets(_tacacs_settings)
        db_tacacs_settings.update({}, {"$set": encoded_tacacs_settings}, upsert=True)


def read_ini_file():
    global app_cfg
    ini_cstor_lite_mode = None
    ini_burnside_mode = None
    ini_capture_mode = app_cfg.get('mode', 'capture_mode', None)
    if ini_capture_mode:
        print("found capture mode setting in ini file: {}".format(ini_capture_mode))
        if 'libpcap' in str(ini_capture_mode).lower():
            ini_cstor_lite_mode = True
            ini_capture_mode = "libpcap"
        elif 'burnside' in str(ini_capture_mode).lower():
            ini_burnside_mode = True
            ini_capture_mode = "burnside"
        elif 'myricom' in str(ini_capture_mode).lower():
            ini_capture_mode = "myricom"
        elif 'dpdk' in str(ini_capture_mode).lower():
            ini_capture_mode = "dpdk"
    else:
        ini_cstor_lite_mode = app_cfg.get('mode', 'cstor_lite_mode', False)
        if str(ini_cstor_lite_mode).lower() in ['true', '1']:
            ini_cstor_lite_mode = True
        ini_burnside_mode = app_cfg.get('mode', 'burnside_mode', False)
        if str(ini_burnside_mode).lower() in ['true', '1']:
            ini_burnside_mode = True

    return ini_capture_mode, ini_cstor_lite_mode, ini_burnside_mode


def init_management_interface(cloud_init):
    if baseimage() == 1804 and cloud_init:
        data = None
        if cloud_init.get('dhcp') == "true":
            data = {'dhcp': True}
        else:
            address = cloud_init.get('address')
            gateway = cloud_init.get('gateway')
            nameservers = cloud_init.get('nameservers')
            if is_valid_ip(address) and is_valid_ip(gateway):
                data = {'dhcp': False,
                        'gateway4': gateway,
                        'addresses': [address]
                        }
                # for now we allow provisioning with valid ip addresses only
                if nameservers:
                    for name in [nameservers]:
                        if not is_valid_ip(name):
                            nameservers = None
                if nameservers:
                    data['nameservers'] = {'addresses': [nameservers]}
        if data:
            cfg = ubConfig()
            cfg.set_netplan(data)


def read_cloud_init_data(first_boot):
    try:
        print("Reading user-data file: {}".format(Consts.BOOT_DATA_FILE))
        boot_data = open(Consts.BOOT_DATA_FILE, "r").read()
        init_dict = eval(boot_data)
        print("The cloud initialization dict is: {}".format(init_dict))
    except (OSError, SyntaxError, IOError) as e:
        print("Failed to read initialization file: {} ({})".format(Consts.BOOT_DATA_FILE, e))
        return None
    return init_dict


def check_first_boot():
    first_boot = False
    print("Checking for first boot file: {}".format(Consts.FIRST_BOOT_FILE))
    try:
        # check if this is the first boot
        sz = os.stat(Consts.FIRST_BOOT_FILE).st_size
        print("The first boot file: {} exists ({})".format(Consts.FIRST_BOOT_FILE, sz))
    except OSError:
        first_boot = True
        with open(Consts.FIRST_BOOT_FILE, "w+") as fp:
            fp.write("start time: {}\n".format(time.time()))
    return first_boot


def init_system_settings(db):
    """
    Initializes the system settings
    :return:
    """
    default_settings = {}
    default_settings.update(Consts.DEFAULT_SETTINGS)

    base_image = baseimage()
    vm_type = detect_virtual()
    first_boot = check_first_boot()
    print("Baseimage: {} VM type: {} First boot: {}".format(base_image, vm_type, first_boot))
    factory_cfg = read_factory_config()
    num_drives = read_num_drives()
    capture_mode, cstor_lite_mode, _ = read_ini_file()
    cloud_init = read_cloud_init_data(first_boot)
    print("DEBUG: capture_mode: {} cstor_lite_mode: {}".format(capture_mode, cstor_lite_mode))
    if cloud_init:
        # cloud init overrides the cstor.ini file
        if cloud_init.get('capture_mode', 'myricom'):
            capture_mode = cloud_init.get('capture_mode')
    if vm_type and vm_type.lower() != 'none' and capture_mode != 'libpcap':
        print("Running inside a VM: {} - have to be dpdk and no HA".format(vm_type))
        capture_mode = "dpdk"

    db_system_settings = db.system_settings
    sys_settings = db_system_settings.find_one()
    if sys_settings is not None:
        """
        sys settings exists, just make sure it has all the defaults in case we added new settings
        or some specific value should be used based on code and not configuration
        """
        sys_settings.update({'cstor_lite_mode': False})
        if capture_mode: sys_settings.update({'capture_mode': capture_mode})
        sys_settings.update({'burnside_mode': False})
        sys_settings.update({'num_drives': num_drives})
        if capture_mode == "dpdk":
            sys_settings.update({'ha_cstor': False})
        if sys_settings.get('max_retention_days', 0) == 0:
            sys_settings.update({'max_retention_days': Consts.DEFAULT_RETENTION_DAYS})
        sys_settings.update({'factory': factory_cfg})
        sys_settings.update({'baseimage': base_image})
        for key in sys_settings.copy():
            if key not in default_settings:
                del sys_settings[key]
        for key in default_settings:
            if key not in sys_settings or \
                    (first_boot and key in Consts.SETTINGS_TO_OVERWRITE):
                sys_settings.update({key: default_settings[key]})
        db_system_settings.update(
            {},
            {"$set": sys_settings},
            upsert=True)
    else:
        """
        No system settings initialize them based on .ini and the cloud init data
        """
        default_settings.update({'capture_mode': capture_mode})
        default_settings.update({'num_drives': num_drives})
        default_settings.update({'cstor_lite_mode': False})
        default_settings.update({'burnside_mode': False})
        default_settings.update({'ha_cstor': False})
        default_settings.update({'factory': factory_cfg})
        default_settings.update({'baseimage': base_image})
        default_settings.update({'vm_type': vm_type})
        if cloud_init:
            for key in cloud_init:
                default_settings.update({key: cloud_init.get(key)})
        db_system_settings.insert(default_settings)

    if first_boot and cloud_init:
        init_management_interface(cloud_init)

def parseoptions():
    parser = OptionParser()
    parser.add_option("-p", "--wsgiport", dest="wsgi_port", metavar="WGSI_PORT",
                      help="WSGI PORT ", type="int")
    parser.add_option("-v",
                      action="store_true", dest="verbose", default=False,
                      help="Verbose Bottle output, prints every url being called (default=False)")

    (opts, _) = parser.parse_args()

    if not opts.wsgi_port:
        opts.wsgi_port = Consts.ADMIN_WSGI_PORT

    return opts


# Wait for a file to be created
def wait_for_file(logger, file_path, timeout=120, interval=3):
    elapsed_seconds = 0
    while not os.path.exists(file_path) and elapsed_seconds < timeout:
        gevent.sleep(interval)
        elapsed_seconds += interval
        logger.info("Retrying [elapsed {} of {} seconds]...".format(elapsed_seconds, timeout))
    if os.path.exists(file_path):
        logger.info("File {} is ready".format(file_path))
        return True
    logger.error("File {} is not ready; timeout [ {} seconds ]".format(file_path, timeout))
    return False


def initialize_cprobe(admin, logger, db, sys_settings):
    # cProbe initialization at the end as it can delay the other services
    # due to the dependency on the PF_RING and Zero-copy drivers
    if sys_settings.get('capture_mode', 'myricom') == 'cprobe':
        # Wait for PF_RING and zero-copy drivers' initialization to complete
        # so that initQSFPMode does not race with the driver loading
        # The PF_RING and zero-copy driver initialization are performed
        # in the following service using the script 'start_capture_driver'
        # /usr/lib/systemd/system/capture_driver.service
        logger.info("Waiting to PF_RING drivers to be initialized...")
        if not wait_for_file(logger, Consts.CPROBE_PF_RING_INIT):
            logger.info("Skipping cProbe service initialization")
            return
        logger.info("PF_RING drivers' initialization is complete")
        # Stopping nprobe processes is necessary before the MTU configuration
        # If MTU is configured while any network interface is in use by these
        # processes, it can cause kernel errors.
        cProbeControl(db, logger).stop(True)
        gevent.sleep(2)
        # Start cprobe services
        try:
            admin.initQSFPMode()
            admin.initMTUSize()
            # Use a new instance of cProbe so that the initialization sequences
            # in the constructor is run again. This helps re-read a few configuration
            # such as enable_balancer settings that might be modified during the previous
            # initialization due to changes in qsfp mode.
            cProbeControl(db, logger).init_services()
        except Exception as e:
            logger.error("Failed to start cprobe - {}".format(str(e)))
            traceback.print_stack(limit=6)

def main():
    bottle.BaseRequest.MEMFILE_MAX = 100 * 1024 * 1024

    global options
    options = parseoptions()

    application_path = ""
    app_cfg_filename = None
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
        app_cfg_filename = os.path.abspath(os.path.join(application_path, '../../../.cstor', Consts.INI_MYCONFIG))
    elif __file__:
        application_path = os.path.dirname(__file__)
        app_cfg_filename = os.path.abspath(os.path.join(application_path, '../../../../.cstor', Consts.INI_MYCONFIG))
    main_dir = os.path.abspath(os.path.join(application_path, ".."))

    try:
        client = MongoClient('127.0.0.1', 27017)
    except pymongo.errors.ConnectionFailure:
        start_mongod()
        client = MongoClient('127.0.0.1', 27017)
    db = client.burnside_db

    global app_cfg
    app_cfg = Myappconfig(app_cfg_filename)
    print("App config file name: %s status: %s" % (app_cfg_filename, app_cfg.status))

    init_system_settings(db)
    user_store = UserStore(db)
    user_management = LocalUserService(user_store)
    # initialize the default users
    verify_store(user_store)
    sys_settings_store = SystemSettingsStore(db)
    ssh_config = SshConfig(sys_settings_store)

    sys_settings = db.system_settings.find_one()
    capture_mode = sys_settings.get('capture_mode')
    enable_pcap_auto_restart = sys_settings.get('enable_pcap_auto_restart', False)
    print ("DEBUG: capture_mode {}".format(capture_mode))
    dl = debug_level(sys_settings['debug_level'])
    logger = MyLogging.MyLogger("admin_app", logfile=None, console=sys_settings['consolelog'],
                                level=dl,
                                udp_dest=sys_settings['udp_dest'], udp_port=sys_settings['udp_port'])
    acl_config = ACLConfig(settings_store=sys_settings_store, acl_store=AclConfigurationStore(db), logger=logger)

    if capture_mode and 'dpdk' in capture_mode:
        capture_nic_index = sys_settings['capture_nic_index']
        rc, num_nics = init_dpdk_nics(capture_nic_index)
        wr = db.system_setting_settings.update(
            {},
            {"$set": {'num_nics': num_nics}},
            upsert=True)
        init_dpdk_nics(capture_nic_index)
    init_tacacs_settings(db)
    if capture_mode and 'myricom' in capture_mode:
        set_smp_affinity(capture_mode)
    if enable_pcap_auto_restart:
        logger.info("Enabling and starting the pcap auto restart daemon")
        control_process('pcap_restart.timer', 'enable')
        control_process('pcap_restart.timer', 'start')
    else:
        logger.info("Stopping and disabling the pcap auto restart daemon")
        control_process('pcap_restart.timer', 'stop')
        control_process('pcap_restart.timer', 'disable')
    control_process('queryapp', 'start')
    if sys_settings.get('capture_mode', 'myricom') != 'cprobe':
        logger.info("The initialization is complete - kicking off the cleanup process to continue the startup process")
        control_process('cleanup', 'start')

    erase_logger = MyLogging.MyLogger(appname="DiskClean", logfile=SECURE_ERASE_LOG)

    bottleapp = Bottle(__name__)
    admin = CstorAdminApi(
        bottleapp=bottleapp,
        mongo_client=client,
        user_management=user_management,
        ssh_config=ssh_config,
        acl_config=acl_config,
        logger=logger,
        disk_erase_logger=erase_logger
    )

    # Initialize cProbe after instantiating CstorAdminApi
    # but before running bottle app
    initialize_cprobe(admin, logger, db, sys_settings)

    try:
        with open(os.path.join(main_dir, Consts.UPDATE_VERSION_FILE), 'r') as version_fd:
            for line in version_fd.readlines():
                if "version:" in line:
                    the_version = line.split('\n')[0].split()[1]
                    logger.info("SW Version: {}".format(the_version))
    except IOError:
        logger.warn("Version file is missing")

    host = '127.0.0.1'
    logger.info("Starting admin bubble at {}".format(options.wsgi_port))
    try:
        if dl == DEBUG:
            run(bottleapp, host=host, port=options.wsgi_port,
                debug=True, quiet=False, server='gevent',  # 'geventSocketIO'
                reloader=False)
        else:
            run(bottleapp, host=host, port=options.wsgi_port,
                debug=False, quiet=True, server='gevent',  # 'geventSocketIO'
                reloader=False)
    except socket.error:
        # a process is listening on the port - identify it
        my_cmd = "netstat -tulpn | grep {} ".format(options.wsgi_port)
        p = gevent.subprocess.Popen(my_cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, shell=True)
        sout, serr = p.communicate()
        logger.error("Can't start listening on port {}. Another process is listening:\n{}".
                     format(options.wsgi_port, sout))
        if sout:
            items = sout.split()
            print(items[6])
        sys.exit(-3)


if __name__ == "__main__":
    main()

