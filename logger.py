# coding=utf-8
# !/usr/bin/python
"""
    Class to implement convenience logger, which is used consistently for the application
     and extended or replaced in the future as needed and makes sense


    #TODO: extend the warning and error to emit a message (syslog/udp) to a remote destination (or more than one)
    # as specified in the conifg file and also enable/disable from config

    © 2007- 2014  cPacket Networks Inc. All Rights Reserved.
"""

import logging
import logging.handlers
import socket  # for udp alert
import syslog

class MyLogger:
    def __init__(self, appname='', logfile="", console=0, level=logging.DEBUG,
                 udp_dest='127.0.0.1', udp_port=0):

        # create logger
        self.appname = appname
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

        # formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s: %(message)s')
        formatter = logging.Formatter('%(levelname)s: %(name)s: %(message)s')
        # adding the module name and line number
        # formatter = logging.Formatter('%(asctime)s - %(levelname)-8s
        # - %(name)-16s - %(message)s [%(module)s:%(lineno)d]')

        # set the level from the constructor parameter
        self.level = level

        if logfile is not None and logfile != "":  # output to a rotating file 100MB
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s: %(message)s')
            fh = logging.handlers.RotatingFileHandler(filename=logfile, maxBytes=100000000, backupCount=3)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            logger.addHandler(fh)

        if console:
            ch.setFormatter(formatter)
            logger.addHandler(ch)

        self.logger = logger
        syslog.openlog(self.appname)
        self.udp_alert_enable = False
        try:
            udp_port = int(udp_port)
        except (ValueError, TypeError):
            udp_port = -1
        if (2 ** 16 - 1) > udp_port > 0:  # destination port was not set from config file yet
            self.udp_alert_enable = True
            self.udp_alert_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_alert_dest_addr = (udp_dest, udp_port)

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warn(self, msg):
        self.logger.warn(msg)
        self.udp_alert('{}: Warning - {}'.format(self.appname, msg))
        syslog.syslog(syslog.LOG_WARNING, msg)

    def error(self, msg):
        self.logger.error(msg)
        self.udp_alert('{}: Error - {}'.format(self.appname, msg))
        syslog.syslog(syslog.LOG_ERR, msg)

    def critical(self, msg):
        self.logger.critical(msg)
        self.udp_alert('{}: Critical - {}'.format(self.appname, msg))
        syslog.syslog(syslog.LOG_CRIT, msg)

    def udp_alert(self, msg='TEST'):
        """
        mechanism to send a udp alert to a desired destination
        e.g. self.udp_alert('category: access text: "communication issues" device: ' + d)
        keywords - category: [limit/threshold, info, syslog, access, appdev, ''],
        level:, device:, port:, filter:, text: "some text
        """
        if self.udp_alert_enable:
            self.udp_alert_socket.sendto(msg, self.udp_alert_dest_addr)


if __name__ == '__main__':
    my_logger = MyLogger('test', logfile="", console=1)

    # 'application' code
    my_logger.debug('debug message')
    my_logger.info('info message')
    my_logger.warn('warn message')
    my_logger.error('error message')
    my_logger.critical('critical message')
