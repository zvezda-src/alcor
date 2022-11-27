


"""Module holding different constants."""


import re
import socket

from alcor._constants import *
from alcor._vcsversion import *
from alcor import compat
from alcor import pathutils

ALLOCATABLE_KEY = "allocatable"
FAILED_KEY = "failed"

DAEMONS_LOGFILES = \
    dict((daemon, pathutils.GetLogFilename(DAEMONS_LOGBASE[daemon]))
         for daemon in DAEMONS_LOGBASE)

DAEMONS_EXTRA_LOGFILES = \
  dict((daemon, dict((extra,
       pathutils.GetLogFilename(DAEMONS_EXTRA_LOGBASE[daemon][extra]))
       for extra in DAEMONS_EXTRA_LOGBASE[daemon]))
         for daemon in DAEMONS_EXTRA_LOGBASE)

IE_MAGIC_RE = re.compile(r"^[-_.a-zA-Z0-9]{5,100}$")

EXT_PLUGIN_MASK = re.compile("^[a-zA-Z0-9_-]+$")

JOB_ID_TEMPLATE = r"\d+"
JOB_FILE_RE = re.compile(r"^job-(%s)$" % JOB_ID_TEMPLATE)

HVC_DEFAULTS[HT_XEN_HVM][HV_VNC_PASSWORD_FILE] = pathutils.VNC_PASSWORD_FILE

del re, socket, pathutils, compat
