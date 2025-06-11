# coding=utf-8
# !/usr/bin/python
"""
    Class to implement convenience logger, which is used consistently for the application
     and extended or replaced in the future as needed and makes sense


    # TODO: extend the warning and error to emit a message (syslog/udp) to a remote destination (or more than one)
    # as specified in the ocnifg file and also enable/disable from config

    © 2007- 2014  cPacket Networks Inc. All Rights Reserved.
"""

import time
import traceback
import logging
import logging.handlers
import socket  # for udp alert
# from MyAppconfig import Myappconfig  ### should not import to avoid circular dependencies


class MyLogger:
    def __init__(self, appname='', logfile="", console=0, level=logging.DEBUG, stop_on_fail=False):
        self.stop_on_fail = stop_on_fail
        # create logger
        logger = logging.getLogger(appname)
        logger.setLevel(level)  # logging.DEBUG)

        # create handler and set level to debug
        ch = logging.StreamHandler()
        ch.setLevel(level)  # logging.DEBUG)

        # create formatter
        # %(pathname)s:%(lineno)d
        # Location:           %(pathname)s:%(lineno)d
        # Module:             %(module)s
        # Function:           %(funcName)s
        # Time:               %(asctime)s

        # formatter = logging.Formatter('%(asctime)s - %(levelname)-8s - %(name)-16s - %(message)s')
        formatter = logging.Formatter('%(levelname)-8s: %(name)-16s: %(message)s')
        # adding the module name and line number
        # formatter = logging.Formatter('%(asctime)s - %(levelname)-8s
        # - %(name)-16s - %(message)s [%(module)s:%(lineno)d]')

        # set the level from the constructor parameter
        self.level = level

        if logfile != "":  # output to a rotating file 100MB
            fh = logging.handlers.RotatingFileHandler(filename=logfile, maxBytes=100000000, backupCount=3)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            logger.addHandler(fh)

        if console:
            ch.setFormatter(formatter)
            logger.addHandler(ch)

        self.logger = logger

    def tc_info(self, msg):
        self.logger.info("TC info ##teamcity[message text='{}' status='NORMAL']".format(msg))

    def tc_warn(self, msg):
        self.logger.warning("TC warning ##teamcity[message text='{}' status='WARNING']".format(msg))

    def tc_error(self, msg):
        self.logger.error("TC error ##teamcity[message text='{}' status='WARNING']".format(msg))

    def tc_test_start(self, name):
        self.logger.info("test start ##teamcity[testStarted name='{}' timestamp='{}.000']".
                    format(name, time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time()))))

    def tc_test_finished(self, name):
        self.logger.info("test end ##teamcity[testFinished name='{}' timestamp='{}.000']".
                    format(name, time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time()))))

    def tc_test_failed(self, name, msg):
        self.logger.error("test failed ##teamcity[testFailed name='{}' message='{}' details='{}']".
                     format(name, msg, traceback.print_exc(limit=4)))
        if self.stop_on_fail:
            exit(-1)

    def tc_test_suite_start(self, name):
        self.logger.info("test suite start ##teamcity[testSuiteStarted name='{}' timestamp='{}.000']".
                    format(name, time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time()))))

    def tc_test_suite_finished(self, name):
        self.logger.info("test suite end ##teamcity[testSuiteFinished name='{}' timestamp='{}.000']".
                    format(name, time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time()))))

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warn(self, msg):
        self.logger.warning(msg)

    # udp_alert('category: appdev  Warn - ' + msg)

    def error(self, msg):
        self.logger.error(msg)
        # udp_alert('category: appdev  Error - ' + msg)

    def critical(self, msg):
        self.logger.critical(msg)

        udp_alert('category: appdev  Critical - ' + msg)

INI_MYCONFIG = "myconfig.ini"

def udp_alert(txt='TEST', dest_addr='127.0.0.1', port_indx=-1):
    """
    mechanism to send a udp alert to a desired destination (port_indx from config file)
    e.g. udp_alert('category: access text: "communication issues" device: ' + d)

    keywords - category: [limit/threshold, info, syslog, access, appdev, ''],
    level:, device:, port:, filter:, text: "some text
    """
    if port_indx < 2:
        # ensure that configuration is set only once
        port_indx = udp_alert.alert_socket_dest[1]  # 2nd element of the two tuple (see function attribute below)

        if port_indx < 2 or port_indx > 2 ** 16 - 1:  # destination port was not set from config file yet
            try:
                # use explicit call to config parser (and not my module) to avoid circular
                #  dependencies between modules MyLogging and MyAppconfig
                import configparser

                cfg = configparser.ConfigParser()
                cfg.read(INI_MYCONFIG)
                port_indx = int(cfg.get('ports', 'udp_alerts'))
                udp_alert.enable = cfg.get('DEFAULT', 'dev_udp_alerts')
            except Exception:
                port_indx = -1
                udp_alert.enable = None
                # print 'udp_alert() setup failed - incorrect port (%s) from config or no config file: ' % str(port_indx)

    # destination for the udp alert
    udp_alert.alert_socket_dest = (dest_addr, port_indx)

    if port_indx > 1:
        if udp_alert.enable and udp_alert.enable.lower()[0] == 'y':  # if "yes" in config file
            udp_alert.alert_socket.sendto(txt.encode(), udp_alert.alert_socket_dest)


# function attribute 
udp_alert.alert_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_alert.alert_socket_dest = ('', -1)
udp_alert.enable = None

if __name__ == '__main__':
    my_logger = MyLogger('test', logfile="", console=1)

    # 'application' code
    my_logger.debug('debug message')
    my_logger.info('info message')
    my_logger.warning('warn message')
    my_logger.error('error message')
    my_logger.critical('critical message')
