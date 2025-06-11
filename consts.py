from logging import DEBUG

COLLECT_VITALS_INTERVAL = 60
LOG_LINES_LIMIT = 5000
OPT_BIN_PATH = '/opt/bin'
HOST_PASSWD_PATH = '/etc/passwd'
HOST_TIMEZONE = '/etc/timezone'
HOST_USER_DIR = '/home/cpacket'
REMOTE_CIPHER_KEY = [56, 46, 80, 82, 120, 91, 75, 57, 66, 103, 56, 67, 70, 76, 48, 51, 110, 56, 92]
REMOTE_HASH_REVISION_2 = 'rev2'
# Markers for machine generated sections in config files
CSTOR_CONFIG_BEGIN = '### BEGIN CSTOR CONFIG'
CSTOR_CONFIG_END = '### END CSTOR CONFIG'
SECURE_ERASE_LOG = '/var/log/secure_erase.log'
# Description of patterns supported by scrub utility.
SECURE_ERASE_PATTERN_MAPPING = {
    'nnsa': '3-pass, NNSA NAP-14.1-C',
    'dod': '3-pass, DoD 5220.22-M',
    'bsi': '9-pass, BSI',
    'usarmy': '3-pass, US Army AR380-19',
    'random': '1-pass, One Random Pass',
    'random2': '2-pass, Two Random Passes',
    'schneier': '7-pass, Bruce Schneier Algorithm',
    'pfitzner7': '7-pass, Roy Pfitzner 7-random-pass method',
    'pfitzner33': '33-pass, Roy Pfitzner 33-random-pass method',
    'gutmann': '35-pass, Gutmann',
    'fastold': '4-pass, pre v1.7 scrub (skip random)',
    'old': '5-pass, pre v1.7 scrub',
    'dirent': '6-pass, dirent',
    'fillzero': '1-pass, Quick Fill with 0x00',
    'fillff': '1-pass, Quick Fill with 0xff',
    'verify': '1-pass, Quick Fill with 0x00 and verify'
    }

ACL_CLUSTER = 'cluster'
ACL_WHITELIST = 'whitelist'

class Consts(object):

    PCAP_PROCESS_COUNT = 4
    SYSD_PROCESSES = ('dpdk_snf', 'cstor_snf', 'queryapp', 'cleanup', 'pcap@0', 'pcap@1', 'pcap@2', 'pcap@3',
                      'stats', 'rt', 'dhcp_snf', 'background', 'session_app', 'chrony', 'ptpd', 'ssh',
                      'mongodb', 'ipmi_tool', 'admin_app', 'snmp', 'pcap_restart.timer')

    CPROBE_PROCESSES = ('nprobe@0', 'nprobe@1', 'nprobe@2', 'nprobe@3', 'nprobe@4', 'nprobe@5',
                      'nprobe@6', 'nprobe@7', 'nprobe@8', 'nprobe@9', 'nprobe@10', 'nprobe@11',
                      'cluster@99')
    WSGI_PORT = 5000
    PCAP_PORT = 5100
    ADMIN_WSGI_PORT = 5002
    PAGE_SIZE = 600

    STATIC_FILES_ROOT = "/"

    LOG_FILE = "/tmp/queryapp.log"
    LOG_FILE_MAX_BYTES = 10000000
    LOG_FILE_BACKUP_COUNT = 2

    UPDATE_STAGE_DIR = "/tmp/cstor_stage"
    UPDATE_INTERNAL_BIN_OLD = "CSTORE_image.bin"
    UPDATE_INTERNAL_BIN = "cstor_image.bin"
    UPDATE_MD5SUM_FILE = "info.txt"
    UPDATE_EXPIRED_TIME = 300
    UPDATE_INSTALL_SCRIPT = "install.sh"
    UPDATE_VERSION_FILE = "version.txt"
    # This will hold major Platform revision.
    UPDATE_PLATFORM_VERSION = "platform_support.txt"
    # This file will hold the os package version of a big_bin
    UPDATE_OS_PACKAGE_VERSION = "os_package_version"
    UPDATE_PASSWD = "0cb454c3095d4c183585ce2759ff06d1"

    INI_MYCONFIG = "cstor.ini"
    INI_FACTORYCONFIG = "/home/cpacket/.cstor/factory/cfg_factory.ini"
    BASEIMAGE_FILE = "/home/cpacket/.cstor/baseimage"
    FIRST_BOOT_FILE = "/home/cpacket/.cstor/firstboot"
    BOOT_DATA_FILE = "/home/cpacket/boot_config.txt"

    CPROBE_CONF_PATH = "/etc/nprobe/"
    CPROBE_CONF_FILE = "/etc/nprobe/nprobe.conf"
    CPROBE_STATS_FILE = '/home/cpacket/cprobe_stats.log'
    CPROBE_PF_RING_INIT = '/var/run/pf-ring-initialized'
    CPROBE_TRAFFIC_DRIVER = 'i40e'
    CPROBE_CLUSTER_CONF_DIR = '/etc/cluster'
    CPROBE_PFRING_CONF_DIR = '/etc/pf_ring'
    CPROBE_PFRING_STATS_DIR = '/proc/net/pf_ring/stats'
    CPROBE_CLUSTER_ID = 99
    CPROBE_NUM_HUGEPAGES = 4096
    CPROBE_MAX_QUEUES = 12
    CPROBE_NUM_QUEUES_HW = 4
    CPROBE_NUM_QUEUES_SW = 6
    CPROBE_NUM_QUEUES_HW_SUPPORTED = [4, 8, 12]
    CPROBE_NUM_QUEUES_SW_SUPPORTED = [6, 8, 10, 12]
    CPROBE_HASH_MODE = 4
    CPROBE_QUEUE_SLOTS = 32768
    CPROBE_CPU_TIME_PULSE = 0
    CPROBE_TIME_RES_NSEC = 100
    CPROBE_CPU_BALANCER = 1
    CPROBE_CPUS_PROBE = [2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15]
    CPROBE_CONF_FILENAME_FORMAT = "/etc/nprobe/nprobe-{}.conf"
    CPROBE_STATS_FILENAME_FORMAT = '/home/cpacket/cprobe_stats_{}.log'
    CPROBE_IDLE_TIMEOUT = 15
    CPROBE_LIFETIME_TIMEOUT = 60
    CPROBE_FLOW_VERSION = 10
    CPROBE_LOCK_FILE = '/home/cpacket/cprobe.lock'
    CPROBE_LONG_TEMPLATE = "%IPV4_SRC_ADDR %IPV4_DST_ADDR %IPV4_NEXT_HOP" \
                           " %INPUT_SNMP %OUTPUT_SNMP %IN_PKTS %IN_BYTES %OUT_PKTS %OUT_BYTES" \
                           " %FIRST_SWITCHED %LAST_SWITCHED " \
                           " %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %PROTOCOL %SRC_TOS %SRC_AS %DST_AS @NTOPNG"
    CPROBE_SHORT_TEMPLATE = "%IPV4_SRC_ADDR %IPV4_DST_ADDR " \
                            " %IN_PKTS %IN_BYTES %OUT_PKTS %OUT_BYTES" \
                            " %FIRST_SWITCHED %LAST_SWITCHED " \
                            " %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %PROTOCOL @NTOPNG"
    CPROBE_DEFAULT_TEMPLATE = "%IPV4_SRC_ADDR %IPV4_DST_ADDR %INPUT_SNMP %OUTPUT_SNMP %IN_PKTS %IN_BYTES" \
                              " %OUT_PKTS %OUT_BYTES %FIRST_SWITCHED %LAST_SWITCHED %L4_SRC_PORT %L4_DST_PORT" \
                              " %TCP_FLAGS %PROTOCOL %SRC_VLAN %IN_SRC_MAC %IN_DST_MAC %FLOW_END_REASON" \
                              " %L7_PROTO %L7_PROTO_NAME %DNS_QUERY %DNS_QUERY_TYPE %DNS_RET_CODE %DNS_RESPONSE"
    QSFP_CONFIG_UTIL = "/opt/qcu/qcu64e"
    QSFP_CHANNELS_4x10 = 4
    QSFP_MODE_2x40 = "2x40"
    QSFP_MODE_4x10 = "4x10"
    CPROBE_ADAPTER = "XL710"
    QSFP_MODES_SUPPORTED = [QSFP_MODE_2x40, QSFP_MODE_4x10]
    CPROBE_INTERFACES_NONE = 0
    CPROBE_INTERFACES_2x40 = 2
    CPROBE_INTERFACES_4x10 = 4
    QSFP_MODE_UNSUPPORTED = "Unsupported"
    QSFP_MODE_MAP = {
        CPROBE_INTERFACES_NONE: QSFP_MODE_UNSUPPORTED,
        CPROBE_INTERFACES_2x40: QSFP_MODE_2x40,
        CPROBE_INTERFACES_4x10: QSFP_MODE_4x10,
    }
    LSHW_NET_BUSINFO = "lshw -class network -businfo"
    TRAFFIC_ADDRESSES = {'eth2': ['1.2.3.4/24'], 'eth3': ['1.2.3.5/24'], 'eth4': ['1.2.3.6/24'], 'eth5': ['1.2.3.7/24']}
    # Minimum mtu is 68 as per RFC 791 internel protocol
    MTU_SIZE_MIN = 68
    MTU_SIZE_MAX = 9702
    MTU_SIZE_DEFAULT = 1500
    MTU_SIZE_JUMBO = 9000
    # Burnside specific settings
    # These are candidates to move to a configuration file for now they are hard coded here
    LOGICAL_PORTS_PER_DEVICE = 3    # number of input ports in the system - logical setting
    PHY_PORTS_PER_IN = 8    # each port is duplicated for 4 ports
    NUM_PHY_CVU_PORTS = 40  # the number of physical cvu ports
    CSTOR_PORT = 40    # the port to which cstor is connected
    CSTOR_CVU_DEVICE = 0    # the device to which cstor is connected

    MAX_NUM_OF_FILTERS_ON_PORT = 24     # number of possible filters on the port - the cpacket filters not the one use
    # The bits we can use to identify a filter
    FILTER_TRAILER_BITS = [1, 2, 4, 8, 16, 32, 64]

    STATE_IDLE = 10
    STATE_ACTIVE = 20
    STATE_STOPPING = 30

    CVU_STATE_UNKNOWN = 10
    CVU_STATE_ACTIVE = 20

    CVU_MAX_DELTA_TIME = 2

    MAX_HD_UTILIZATION = 0.98

    CVU_CONNECTION_TIMEOUT = 30

    DEFAULT_RETENTION_DAYS = 7

    # these are setting that old cstor versions got it wrong and we want to ensure that
    # they aren't set to a problematic setting
    SETTINGS_TO_OVERWRITE = ['cleanup_period',
                             'cleanup_threshold',
                             'max_time_to_find_a_packet',
                             'max_active_connections'
                             ]

    DEFAULT_SETTINGS_WITH_TYPES = {
        'system_state':                 ('ok', str),
        'log_collection':               ('idle', str),
        'cstor_lite_mode':              (False, bool),
        'burnside_mode':                (False, bool),
        'ipar_mode':                    (False, bool),
        'decap_mode':                   (None, str),
        'baseimage':                    (1804, int),
        'capture_mode':                 ('myricom', str),   # controls the capture mode: Myricom, dpdk etc.
        'consolelog':                   (True, bool),
        'debug_level':                  (DEBUG, int),
        'cleanup_period':               (4, int),
        'cleanup_threshold':            (100, int),    # cleanup threshold in GB
        'udp_alert_enable':             (False, bool),
        'udp_dest':                     ("127.0.0.1", str),
        'udp_port':                     (1222, int),
        'stats_time':                   (2, int),
        'max_time_to_find_a_packet':    (600, int),
        'default_max_download_size':    (1 * 1024 * 1024, int),
        'default_download_q_size':      (100 * 1024 * 1024, int),
        'default_download_q_timeout':   (600, int),
        'num_of_download_threads':      (1, int),
        'num_drives':                   (11, int),
        'ssh':                          ({'enabled': True}, dict),
        'acl':                          ({'enabled': False}, dict),
        'acl_members_limit':            (200, int),
        'snmp':                         ({'enabled': True}, dict),

        # Background task
        'run_background_task':      (True, bool),
        'enable_pcap_auto_restart': (False, bool),
        'cnat_index_threads':       (6, int),
        'update_ip_map_resolution': (3600, int),       # how often to update the ip map in the database (in seconds)
        'ipar_save_pcaps':          (True, bool),      # determines if to save the pcap files when running in IPAR mode
        'ipar_survey_only':         (False, bool),      # determines if to save pcap files or run analysis on

        'num_pcap_bufs':            (12, int),
        'pcap_cpu_mask':            (0x3c, int),      # Default for NFVIS environment - cpu mask for thread_main
        'ha_cstor':                 (False, bool),     # controls running in high-availability mode
        'data_shards':              (8, int),         # in HA mode controls the ratio DATA shards to FEC shards
        'fec_shards':               (1, int),          # in HA mode controls the ratio DATA shards to FEC shards
        'use_compression':          (True, bool),       # controls the compression of data
        'myri_port_num':            (0, int),         # the myri card port to use on cstor 10G
        'myri_ring_size':           (20000, int),     # the myri data ring size
        'max_active_connections':   (300000, int),    # controls the maximum number of active-connections to track
        'max_cps':                  (60000, int),     # controls the maximum number of CPS to track
        'max_ip_count':             (300000, int),    # controls the maximum number of IP endpoints to track
        'eth_dev':                  ('eth0', str),

        'pkt_burst_size':           (1, int),

        'replay_mode':          (False, bool),      # enables the replay feature
        'index_mode':           (True,  bool),      # enables teh indexing of data
        'run_cnat_indexing':    (False, bool),      # enables the CNAT mode
        'run_cflow_mode':       (False, bool),      # enables the TCP analysis mode
        'run_udp_mcast_mode':   (False, bool),      # enables the UDP multicast analysis mode
        'udp_multicast_mode':   ('rtp', str), # 'RTP' or 'MD' (Market Data) processing of UDP multicast streams
        'tcp_session_timeout':  (300, int),        # timeout for TCP sessions without traffic
        'tcp_syn_fail_timeout': (300, int),        # timeout for TCP SYN packet without traffic
        'max_skew_timestamp_seconds': (600, int),        # maximum skew between cvu and cstor timestamps

        'vm_mode':              ("none", str),
        'capture_nic_ip':       ("", str),
        'capture_nic_eth':      ("", str),
        'num_nics':             (2, int),
        'pci_whitelist':        ("", str),
        'capture_nic_index':    (-1, int),          # controls which NIC index to use for capture if negative - ignore
        'core_mask':            ("0x6", str),
        'dpdk_rx_q':            (1, int),
        'dpdk_tx_q':            (1, int),
        'mb_mempool_cache':     (250, int),
        'dpdk_pkt_burst':       (64, int),
        'dpdk_total_num_mbufs': (32768, int),
        'dpdk_promisc_mode':    (False, bool),
        'dpdk_mtu_size':        (2048, int),       # User can set to larger values to support jumbo frames

        'max_files_on_disk':    (60 * 60 * 24 * 30 * 3, int),     # 7,776,000
        'max_retention_days':   (DEFAULT_RETENTION_DAYS, int),   # limiting retention days on the disk (0 => disable)
        'factory':              ({}, dict),
        'send_rtp_stats':       (False, bool),  # controls pushing RTP stats to cclear
        'send_latency_stats':   (False, bool),  # controls pushing one way latency stats to cclear
        'send_esp_stats':       (False, bool),  # controls pushing IPSec stats to cclear
        'send_xdp_stats':       (False, bool),  # controls pushing XDP Market Data Feed stats to cclear
        'send_sys_stats':       (True,  bool),  # controls pushing debug stats to cclear

        'qsfp_mode':            ('', str),
        'mtu_size':             (MTU_SIZE_JUMBO, int),

        'cprobe_if_name':       ('eth2', str),
        'cprobe_enable_balancer': (True, bool),
        'cprobe_num_queues_sw': (CPROBE_NUM_QUEUES_SW, int),
        'cprobe_num_queues_hw': (CPROBE_NUM_QUEUES_HW, int),
        'cprobe_target':        ('none', str),
        'cprobe_target_all':    (True, bool),
        'cprobe_template':      (CPROBE_SHORT_TEMPLATE, str),
        'cprobe_version':       ('8.7.191029', str),
        'cprobe_idle_timeout':  (15, int),
        'cprobe_lifetime_timeout':    (60, int),
        'cprobe_system_id':     ('7D04C4649207AB27', str),
        'cprobe_order_id':      ('1575197442', str),
        'cprobe_license':       (None, str),
        'cprobe_license_date':  (None, str),
        'cprobe_zc_licenses':   (None, list),
        'cprobe_sample_rate':   ('1:1:1', str),
        'cprobe_debug_level':   (1, int),
        'cprobe_advanced_options': ({}, dict),
        'ignore_drive_errors':   (False, bool),
        'use_arista_timestamp': (False, bool),
        'arista_timestamp_mode': ("none", str),
    }

    DEFAULT_SETTINGS = {k: v[0] for k, v in DEFAULT_SETTINGS_WITH_TYPES.iteritems()}
    DEFAULT_SETTINGS_TYPES = {k: v[1] for k, v in DEFAULT_SETTINGS_WITH_TYPES.iteritems()}

    # These are settings that may be useful for debugging purposes only
    STATS_DB_DEFAULT_SETTINGS = {
        'stats_db_server': None,
        'stats_db_port': '443',
        'stats_db_user': 'cclear',
        'stats_db_pswd': 'cclearpw',
        'stats_db_connected': False
    }

    # CNAT default settins
    CNAT_DEFAULT_SETTINGS = {
        "report_syn_attack": False,
        "report_active_sessions": True,
        "report_no_correlations": True,
        "use_vlans": True,
        "infer_direction": True,
        "lookup_imsi": True,
        "cnat_match_timeout": 0.3,
        "set_cvu_bw_list": False
    }

    MY_LOGS = ['/var/log/syslog',
               '/var/log/upstart/queryapp.log',
               '/var/log/upstart/background.log',
               '/var/log/upstart/capture.log',
               '/var/log/upstart/cstor_snf.log',
               '/var/log/upstart/cleanup.log',
               '/var/log/mongodb/mongod.log',
               '/var/log/upstart/admin_app.log',
               '/var/log/upstart/pcap.log',
               '/var/log/upstart/pcap-*.log',
               '/var/log/upstart/pcap-0.log',
               '/var/log/upstart/pcap-1.log',
               '/var/log/upstart/pcap-2.log',
               '/var/log/upstart/pcap-3.log',
               '/var/log/upstart/stats.log',
               '/var/log/upstart/rt.log',
               '/var/log/nginx/error.log',
               '/var/log/nginx/access.log']

    ZIP_LOGS = ['/var/log/']

    FTP_PORT = 21
    SSH_PORT = 22
    TELNET_PORT = 23
    ACTIVE_PORTS_LIST = [FTP_PORT, SSH_PORT, TELNET_PORT]

    # Using SG_* prefix, 0x22, unused code value, ioctl cmd to enable SED
    CP_ENABLE_SED_MAX_LEVEL = 0x22DE

    SED_MODELS = ["ST4000NM006A",
                  "ST4000NM010A",
                  "ST3000NM002A",
                  "ST2000NM006A",
                  "ST1000NM002A",
                  "ST4000NM013A",
                  "ST3000NM004A",
                  "ST4000NM0053",
                  "ST3000NM0053",
                  "ST1000NM0053"]
