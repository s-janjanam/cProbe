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
        self.sys_settings = db.system_settings.find_one({}, {"_id": False})
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
      
    @property
    def sample_rate(self):
        """
        [--sample-rate|-S] pkt_rate:flow_collection_rate:flow_export_rate

        Three different rates can be specified with this option:

            Packet capture sampling rate 'pkt rate'. This rate is effective for interfaces specified with -i and allows
            to control the sampling rate of incoming packets. For example, a sampling rate of 100 will instruct nprobe
            to actually process one packet out of 100, discarding all the others.
            'pkt rate' can be prepended with a '@' to instruct nprobe to only use the sampling rate for the up-scaling,
            without performing any actual sampling. This is particularly useful when incoming packets are already
            sampled on the capture device connected to nprobe but it is still meaningful to have up-scaled statistics.

            Flow collection sampling rate 'flow collection rate'. This rate works when nprobe is in collector mode,
            that is, when option --collector-port is used and specifies the flow rate at which flows being collected
            have been sampled. In this case, no actual sampling is performed on the incoming flows. The specified rate
            is only used to perform the upscaling. For example, a flow with 250 IN_BYTES will be up-scaled by a factor
            equal to the sampling rate. If the sampling rate is 100, a total of 2500 IN_BYTES will be accounted for
            that flow.

            Flow export rate 'flow export rate'. This rate is effective when nprobe exports NetFlow towards a
            downstream collector, that is, when option -n is used. It controls the output sampling. For example, a
            'flow export rate' of 100 will cause nprobe to only export 1 flow out of 100 towards the downstream
            collector.
        """
        pkt_rate = 1
        flow_collection_rate = 1
        flow_export_rate = 1
        sample_rate_str = '{}:{}:{}'.format(pkt_rate, flow_collection_rate, flow_export_rate)
        return self.sys_settings.get('cprobe_sample_rate', sample_rate_str)

    @sample_rate.setter
    def sample_rate(self, pkt_rate=1, flow_collection_rate=1, flow_export_rate=1):
        sample_rate_str = '{}:{}:{}'.format(pkt_rate, flow_collection_rate, flow_export_rate)
        self.db.system_settings.update({}, {"$set": {'cprobe_sample_rate': sample_rate_str}})

    @property
    def advanced_options(self):
        """
        Custom nprobe options added by users
        """
        default_advanced_options = {"enable": False, "options": [{}]}
        advanced_opts = self.sys_settings.get('cprobe_advanced_options', default_advanced_options)
        if "enable" not in advanced_opts:
            advanced_opts['enable'] = False
        if "options" not in advanced_opts:
            advanced_opts['options'] = [{}]
        return advanced_opts

    @property
    def idle_timeout(self):
        return self.sys_settings.get('cprobe_idle_timeout', Consts.CPROBE_IDLE_TIMEOUT)

    @idle_timeout.setter
    def idle_timeout(self, level):
        try:
            self.db.system_settings.update({}, {"$set": {'cprobe_idle_timeout': int(level)}})
        except (TypeError, ValueError) as e:
            self.logger.debug("Failed to set idle timeout: {}".format(level))

    @property
    def lifetime_timeout(self):
        return self.sys_settings.get('cprobe_lifetime_timeout', Consts.CPROBE_LIFETIME_TIMEOUT)

    @lifetime_timeout.setter
    def lifetime_timeout(self, level):
        try:
            self.db.system_settings.update({}, {"$set": {'cprobe_lifetime_timeout': int(level)}})
        except (TypeError, ValueError) as e:
            self.logger.debug("Failed to set life time timeout: {}".format(level))

    @property
    def flow_version(self):
        """
            Used to specify the flow version for exported flows. Supported versions are 5 (v5), 9 (v9) and 10 (IPFIX).
        """
        return self.sys_settings.get('cprobe_flow_version', Consts.CPROBE_FLOW_VERSION)

    @flow_version.setter
    def flow_version(self, ver):
        try:
            self.db.system_settings.update({}, {"$set": {'cprobe_flow_version', int(ver)}})
        except (TypeError, ValueError) as e:
            self.logger.debug("Failed to set the flow version to: {}".format(ver))

    @property
    def version(self):
        return self.sys_settings.get('cprobe_version', 0)

    @property
    def license(self):
        try:
            with open('/etc/nprobe.license', 'r') as f:
                return f.read()
        except (IOError, OSError) as e:
            self.logger.debug("Failed to read license: {}".format(e))
            return None

    @license.setter
    def license(self, lic):
        try:
            with open('/etc/nprobe.license', 'w') as f:
                f.write(lic)
        except (OSError, TypeError, ValueError) as e:
            self.logger.debug("Failed to set license to: {}".format(lic))

    @property
    def zc_licenses(self):
        zc_licenses = self.sys_settings.get('cprobe_zc_licenses')
        if not zc_licenses or len(zc_licenses) <= 0:
            zc_licenses = [{"id": "", "license": "", "date": ""}]
        return zc_licenses

    def get_configuration(self):
        config = {
            'cprobe_target': self.target,
            'cprobe_template': self.template,
            'cprobe_lock': self.lock,
            'cprobe_aggregation': self.aggregation,
            'cprobe_sample_rate': self.sample_rate,
            'cprobe_advanced_options': self.advanced_options,
            'cprobe_dedup': self.dedup,
            'cprobe_flow_version': self.flow_version,
            'cprobe_bi_directional': self.bi_directional,
            'cprobe_debug_level': self.debug_level,
            'cprobe_lifetime_timeout': self.lifetime_timeout,
            'cprobe_idle_timeout': self.idle_timeout,
            'cprobe_system_id': self.system_id,
            'cprobe_version': self.version,
            'cprobe_license': self.license,
            'cprobe_license_date': self.license_date,
            'cprobe_zc_licenses': self.zc_licenses,
        }
        return config

    def _write_target(self, fp):
        try:
            # eliminate inner and outer whitespaces, avoid empty items
            target_list = [t.strip() for t in self.target.strip().split(',') if t.strip()]
            for t in target_list:
                fp.write("--collector={}\n".format(t))
            if self.target_all:
                fp.write("--all-collectors\n")
        except Exception as e:
            self.logger.error("Failed to write targets {}: {}".format(self.target, str(e)))
          
    def write_configuration_nprobe_instance(self, instance_num, interface):
        import pwd
        import grp
        uid = pwd.getpwnam("nprobe").pw_uid
        gid = grp.getgrnam("nprobe").gr_gid
        stats_file = Consts.CPROBE_STATS_FILENAME_FORMAT.format(instance_num)
        conf_file = Consts.CPROBE_CONF_FILENAME_FORMAT.format(instance_num)
        # Create the stats file
        with open(stats_file, "w+") as f:
            pass
        os.chown(stats_file, uid, gid)
        with open(conf_file, "w") as fp:
            fp.write("--interface={}\n".format(interface))
            fp.write("--netflow-engine=0:{}\n".format(instance_num))
            fp.write("--cpu-affinity={}\n".format(Consts.CPROBE_CPUS_PROBE[instance_num]))
            fp.write("--export-thread-affinity={}\n".format(Consts.CPROBE_CPUS_PROBE[instance_num]))
            fp.write("--verbose={}\n".format(self.debug_level))
            self._write_target(fp)
            fp.write("--flow-templ=\"{}\"\n".format(self.template))
            fp.write("--dump-stats={}\n".format(stats_file))
            fp.write("--flow-lock={}\n".format(self.flow_lock_file))
            fp.write("--aggregation={}\n".format(self.aggregation))
            fp.write("--sample-rate={}\n".format(self.sample_rate))
            fp.write("--biflows-export-policy={}\n".format(self.bi_directional))
            fp.write("--flow-version={}\n".format(self.flow_version))
            fp.write("--lifetime-timeout={}\n".format(self.lifetime_timeout))
            fp.write("--idle-timeout={}\n".format(self.idle_timeout))
            if self.dedup:
                fp.write("--enable-ipv4-deduplication\n")
            self._write_advanced_configuration_nprobe(fp)

    def write_configuration_nprobe(self):
        makedirs(Consts.CPROBE_CONF_PATH, exist_ok=True)
        if self.detect_compatible_adapter():
            num = self.num_queues_sw if self.enable_balancer else self.num_queues_hw
            for n in range(0, num):
                interface = self.get_interface_nprobe_instance(n)
                if not interface:
                    # This is a safety check to avoid writing configurations for
                    # an interface that is not available (yet) due to a change in
                    # qsfp mode that has not been applied (by performing a reboot).
                    break
                self.write_configuration_nprobe_instance(n, interface)
            # Remove rest of the config / stats files if present
            for n in range(num, Consts.CPROBE_MAX_QUEUES):
                remove_file(Consts.CPROBE_STATS_FILENAME_FORMAT.format(n), True)
                remove_file(Consts.CPROBE_CONF_FILENAME_FORMAT.format(n), True)
        else:
            interface = sorted(Consts.TRAFFIC_ADDRESSES)[0]
            self.write_configuration_nprobe_instance(0, interface)
        # lock file is common to all nprobe processes
        self._create_lock_file(self.lock)

    def write_configuration_cluster(self):
        makedirs(Consts.CPROBE_CLUSTER_CONF_DIR, exist_ok=True)
        cluster_config_file = "cluster-{}.conf".format(Consts.CPROBE_CLUSTER_ID)
        cluster_config_path = os.path.join(Consts.CPROBE_CLUSTER_CONF_DIR, cluster_config_file)
        # Create a c cluster configuration file if a software balancer is enabled
        if self.enable_balancer and self.detect_compatible_adapter():
            self.logger.debug("Creating cluster configuration {}".format(cluster_config_path))
            interface = sorted(Consts.TRAFFIC_ADDRESSES)[0]
            try:
                with open(cluster_config_path, "w") as fp:
                    fp.write("-i=zc:{}\n".format(interface))
                    fp.write("-c={}\n".format(Consts.CPROBE_CLUSTER_ID))
                    fp.write("-n={}\n".format(self.num_queues_sw))
                    fp.write("-m={}\n".format(Consts.CPROBE_HASH_MODE))
                    fp.write("-S={}\n".format(Consts.CPROBE_CPU_TIME_PULSE))
                    fp.write("-R={}\n".format(Consts.CPROBE_TIME_RES_NSEC))
                    fp.write("-g={}\n".format(Consts.CPROBE_CPU_BALANCER))
                    fp.write("-q={}\n".format(Consts.CPROBE_QUEUE_SLOTS))
                    fp.write("-p\n")
            except OSError as e:
                self.logger.debug("error in writing to {}: {}".format(cluster_config_path, e))
        else:
            self.logger.debug("Removing cluster configuration {}".format(cluster_config_path))
            try:
                if os.path.isfile(cluster_config_path):
                    os.remove(cluster_config_path)
            except OSError as e:
                self.logger.debug("error in removing {}: {}".format(cluster_config_path, e))

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
