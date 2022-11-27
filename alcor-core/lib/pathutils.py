


"""Module containing constants and functions for filesystem paths.

"""

from alcor import _constants
from alcor import compat
from alcor import vcluster


DEFAULT_FILE_STORAGE_DIR = "/srv/alcor/file-storage"
DEFAULT_FILE_STORAGE_DIR = vcluster.AddNodePrefix(DEFAULT_FILE_STORAGE_DIR)
DEFAULT_SHARED_FILE_STORAGE_DIR = "/srv/alcor/shared-file-storage"
DEFAULT_SHARED_FILE_STORAGE_DIR = \
    vcluster.AddNodePrefix(DEFAULT_SHARED_FILE_STORAGE_DIR)
DEFAULT_GLUSTER_STORAGE_DIR = "/var/run/alcor/gluster"
DEFAULT_GLUSTER_STORAGE_DIR = \
    vcluster.AddNodePrefix(DEFAULT_GLUSTER_STORAGE_DIR)
EXPORT_DIR = vcluster.AddNodePrefix(_constants.EXPORT_DIR)
BACKUP_DIR = vcluster.AddNodePrefix(_constants.BACKUP_DIR)
OS_SEARCH_PATH = _constants.OS_SEARCH_PATH
ES_SEARCH_PATH = _constants.ES_SEARCH_PATH
SSH_CONFIG_DIR = _constants.SSH_CONFIG_DIR
XEN_CONFIG_DIR = vcluster.AddNodePrefix(_constants.XEN_CONFIG_DIR)
SYSCONFDIR = vcluster.AddNodePrefix(_constants.SYSCONFDIR)
TOOLSDIR = _constants.TOOLSDIR
PKGLIBDIR = _constants.PKGLIBDIR
SHAREDIR = _constants.SHAREDIR
LOCALSTATEDIR = vcluster.AddNodePrefix(_constants.LOCALSTATEDIR)

DAEMON_UTIL = _constants.PKGLIBDIR + "/daemon-util"
IMPORT_EXPORT_DAEMON = _constants.PKGLIBDIR + "/import-export"
KVM_CONSOLE_WRAPPER = _constants.PKGLIBDIR + "/tools/kvm-console-wrapper"
KVM_IFUP = _constants.PKGLIBDIR + "/kvm-ifup"
PREPARE_NODE_JOIN = _constants.PKGLIBDIR + "/prepare-node-join"
SSH_UPDATE = _constants.PKGLIBDIR + "/ssh-update"
NODE_DAEMON_SETUP = _constants.PKGLIBDIR + "/node-daemon-setup"
SSL_UPDATE = _constants.PKGLIBDIR + "/ssl-update"
XEN_CONSOLE_WRAPPER = _constants.PKGLIBDIR + "/tools/xen-console-wrapper"
CFGUPGRADE = _constants.PKGLIBDIR + "/tools/cfgupgrade"
POST_UPGRADE = _constants.PKGLIBDIR + "/tools/post-upgrade"
ENSURE_DIRS = _constants.PKGLIBDIR + "/ensure-dirs"
XEN_VIF_METAD_SETUP = _constants.PKGLIBDIR + "/vif-alcor-metad"
ETC_HOSTS = vcluster.ETC_HOSTS

DATA_DIR = LOCALSTATEDIR + "/lib/alcor"
LOCK_DIR = LOCALSTATEDIR + "/lock"
LOG_DIR = LOCALSTATEDIR + "/log/alcor"
RUN_DIR = LOCALSTATEDIR + "/run/alcor"

DEFAULT_MASTER_SETUP_SCRIPT = TOOLSDIR + "/master-ip-setup"

SSH_HOST_DSA_PRIV = _constants.SSH_HOST_DSA_PRIV
SSH_HOST_DSA_PUB = _constants.SSH_HOST_DSA_PUB
SSH_HOST_RSA_PRIV = _constants.SSH_HOST_RSA_PRIV
SSH_HOST_RSA_PUB = _constants.SSH_HOST_RSA_PUB
SSH_PUB_KEYS = DATA_DIR + "/alcor_pub_keys"

BDEV_CACHE_DIR = RUN_DIR + "/bdev-cache"
DISK_LINKS_DIR = RUN_DIR + "/instance-disks"
SOCKET_DIR = RUN_DIR + "/socket"
CRYPTO_KEYS_DIR = RUN_DIR + "/crypto"
IMPORT_EXPORT_DIR = RUN_DIR + "/import-export"
INSTANCE_STATUS_FILE = RUN_DIR + "/instance-status"
INSTANCE_REASON_DIR = RUN_DIR + "/instance-reason"
UIDPOOL_LOCKDIR = RUN_DIR + "/uid-pool"
LIVELOCK_DIR = RUN_DIR + "/livelocks"
LUXID_MESSAGE_DIR = RUN_DIR + "/luxidmessages"

SSCONF_LOCK_FILE = LOCK_DIR + "/alcor-ssconf.lock"

CLUSTER_CONF_FILE = DATA_DIR + "/config.data"
LOCK_STATUS_FILE = DATA_DIR + "/locks.data"
TEMP_RES_STATUS_FILE = DATA_DIR + "/tempres.data"
RAPI_CERT_FILE = DATA_DIR + "/rapi.pem"
CONFD_HMAC_KEY = DATA_DIR + "/hmac.key"
SPICE_CERT_FILE = DATA_DIR + "/spice.pem"
SPICE_CACERT_FILE = DATA_DIR + "/spice-ca.pem"
CLUSTER_DOMAIN_SECRET_FILE = DATA_DIR + "/cluster-domain-secret"
SSH_KNOWN_HOSTS_FILE = DATA_DIR + "/known_hosts"
RAPI_DATA_DIR = DATA_DIR + "/rapi"
RAPI_USERS_FILE = RAPI_DATA_DIR + "/users"
QUEUE_DIR = DATA_DIR + "/queue"
INTENT_TO_UPGRADE = DATA_DIR + "/intent-to-upgrade"
CONF_DIR = SYSCONFDIR + "/alcor"
XEN_IFUP_OS = CONF_DIR + "/xen-ifup-os"
USER_SCRIPTS_DIR = CONF_DIR + "/scripts"
VNC_PASSWORD_FILE = CONF_DIR + "/vnc-cluster-password"
HOOKS_BASE_DIR = CONF_DIR + "/hooks"
FILE_STORAGE_PATHS_FILE = CONF_DIR + "/file-storage-paths"
RESTRICTED_COMMANDS_DIR = CONF_DIR + "/restricted-commands"

NODED_CERT_FILE = DATA_DIR + "/server.pem"
NODED_CLIENT_CERT_FILE = DATA_DIR + "/client.pem"

NODED_CERT_MODE = 0o440

RESTRICTED_COMMANDS_LOCK_FILE = LOCK_DIR + "/alcor-restricted-commands.lock"

WATCHER_LOCK_FILE = LOCK_DIR + "/alcor-watcher.lock"

WATCHER_GROUP_STATE_FILE = DATA_DIR + "/watcher.%s.data"

WATCHER_GROUP_INSTANCE_STATUS_FILE = DATA_DIR + "/watcher.%s.instance-status"

WATCHER_PAUSEFILE = DATA_DIR + "/watcher.pause"

EXTERNAL_MASTER_SETUP_SCRIPT = USER_SCRIPTS_DIR + "/master-ip-setup"

MASTER_SOCKET = SOCKET_DIR + "/alcor-master"
QUERY_SOCKET = SOCKET_DIR + "/alcor-query"
WCONFD_SOCKET = SOCKET_DIR + "/alcor-wconfd"
METAD_SOCKET = SOCKET_DIR + "/alcor-metad"

LOG_OS_DIR = LOG_DIR + "/os"
LOG_ES_DIR = LOG_DIR + "/extstorage"
LOG_XEN_DIR = LOG_DIR + "/xen"
LOG_KVM_DIR = LOG_DIR + "/kvm"

JOB_QUEUE_LOCK_FILE = QUEUE_DIR + "/lock"
JOB_QUEUE_VERSION_FILE = QUEUE_DIR + "/version"
JOB_QUEUE_SERIAL_FILE = QUEUE_DIR + "/serial"
JOB_QUEUE_ARCHIVE_DIR = QUEUE_DIR + "/archive"
JOB_QUEUE_DRAIN_FILE = QUEUE_DIR + "/drain"

ALL_CERT_FILES = compat.UniqueFrozenset([
  NODED_CERT_FILE,
  RAPI_CERT_FILE,
  SPICE_CERT_FILE,
  SPICE_CACERT_FILE,
  ])


def GetLogFilename(daemon_name):
  """Returns the full path for a daemon's log file.

  """
  return "%s/%s.log" % (LOG_DIR, daemon_name)


LOG_WATCHER = GetLogFilename("watcher")
LOG_COMMANDS = GetLogFilename("commands")
LOG_BURNIN = GetLogFilename("burnin")
