# Control the operations of nprobe
from gevent import monkey
monkey.patch_all()

from HelperFunctions import control_process
import os
from consts import Consts
import gevent
import traceback
from HelperFunctions import makedirs
from HelperFunctions import remove_file
import re
from cpConfig.ub18cfg import Ub18Cfg as ubConfig


class cProbeControl(object):
    def __init__(self, db, logger):
        self.db = db
        self.ubCfg = ubConfig()
        self.sys_settings = JSONSettings('system_settings.json')
        self.logger = logger
        self._my_service_name = 'nprobe'
        self.get_nprobe_version()
        lic = self.sys_settings.get('cprobe_license', None)
        if lic:
            self.license = lic
        self._compatible_adapter_present = None
        self._qsfp_mode = None
        self.get_num_queues_hw()
        self.get_num_queues_sw()

    def target(self):
        return self.sys_settings.get('cprobe_target', 'none')

    def template(self):
        return self.sys_settings.get('cprobe_template', Consts.CPROBE_DEFAULT_TEMPLATE)

    def sample_rate(self):
        pkt_rate = 1
        flow_collection_rate = 1
        flow_export_rate = 1
        sample_rate_str = '{}:{}:{}'.format(pkt_rate, flow_collection_rate, flow_export_rate)
        return self.sys_settings.get('cprobe_sample_rate', sample_rate_str)

    def sample_rate(self, pkt_rate=1, flow_collection_rate=1, flow_export_rate=1):
        sample_rate_str = '{}:{}:{}'.format(pkt_rate, flow_collection_rate, flow_export_rate)
        self.sys_settings.set('cprobe_sample_rate', sample_rate_str)
        
    def idle_timeout(self):
        return self.sys_settings.get('cprobe_idle_timeout', Consts.CPROBE_IDLE_TIMEOUT)

    def idle_timeout(self, level):
        self.sys_settings.set('cprobe_idle_timeout', level)

    def lifetime_timeout(self):
        return self.sys_settings.get('cprobe_lifetime_timeout', Consts.CPROBE_LIFETIME_TIMEOUT)

    def lifetime_timeout(self, level):
        self.sys_settings.set('cprobe_lifetime_timeout', level)

    def flow_version(self):
        return self.sys_settings.get('cprobe_flow_version', Consts.CPROBE_FLOW_VERSION)

    def flow_version(self, ver):
        self.sys_settings.set('cprobe_flow_version', ver)

    def license(self):
        try:
            with open('/etc/nprobe.license', 'r') as f:
                return f.read()
        except (IOError, OSError) as e:
            return None

    def license(self, lic):
        try:
            with open('/etc/nprobe.license', 'w') as f:
                f.write(lic)
        except (OSError, TypeError, ValueError) as e:
            self.logger.debug("Failed to set license to: {}".format(lic))

    def zc_licenses(self):
        zc_licenses = self.sys_settings.get('cprobe_zc_licenses')
        if not zc_licenses or len(zc_licenses) <= 0:
            zc_licenses = [{"id": "", "license": "", "date": ""}]
        return zc_licenses

    def get_configuration(self):
        config = {
            'cprobe_target': self.target,
            'cprobe_template': self.template,
            'cprobe_sample_rate': self.sample_rate,
            'cprobe_flow_version': self.flow_version,
            'cprobe_lifetime_timeout': self.lifetime_timeout,
            'cprobe_idle_timeout': self.idle_timeout,
            'cprobe_system_id': self.system_id,
            'cprobe_version': self.version,
            'cprobe_license': self.license,
            'cprobe_license_date': self.license_date,
            'cprobe_zc_licenses': self.zc_licenses,
        }
        return config
          
    def write_configuration_nprobe_instance(self, interface):
        conf_file = Consts.CPROBE_CONF_FILENAME_FORMAT.format(instance_num)
        with open(conf_file, "w") as fp:
            fp.write("--interface={}\n".format(interface))
            fp.write("--cpu-affinity={}\n".format(Consts.CPROBE_CPUS_PROBE[instance_num]))
            fp.write("--export-thread-affinity={}\n".format(Consts.CPROBE_CPUS_PROBE[instance_num]))
            fp.write("--verbose={}\n".format(self.debug_level))
            fp.write("--collector={}\n".format(self.target))
            fp.write("--flow-templ=\"{}\"\n".format(self.template))
            fp.write("--aggregation={}\n".format(self.aggregation))
            fp.write("--sample-rate={}\n".format(self.sample_rate))
            fp.write("--flow-version={}\n".format(self.flow_version))
            fp.write("--lifetime-timeout={}\n".format(self.lifetime_timeout))
            fp.write("--idle-timeout={}\n".format(self.idle_timeout))
            
    def write_configuration_nprobe(self):
        makedirs(Consts.CPROBE_CONF_PATH, exist_ok=True)
        interface = sorted(Consts.TRAFFIC_ADDRESSES)[0]
        self.write_configuration_nprobe_instance(0, interface)

    def write_configuration(self):
        self.write_configuration_cluster()
        self.write_configuration_nprobe()

    def start(self, all_services=False):
        self.write_configuration()
        if self.enable_balancer:
            control_process("cluster@{}".format(Consts.CPROBE_CLUSTER_ID), 'start')
            gevent.sleep(1.0)

        for sname in self.get_service_names(all_services):
            control_process(sname, 'start')

    def stop(self, all_services=False):
        for sname in self.get_service_names(all_services):
            control_process(sname, 'stop')
        if all_services:
            control_process("cluster@{}".format(Consts.CPROBE_CLUSTER_ID), 'stop')

    def restart(self, all_services=False):
        self.write_configuration()
        for sname in self.get_service_names(all_services):
            control_process(sname, 'restart')
