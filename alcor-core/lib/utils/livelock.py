

"""Lockfiles to prove liveliness

When requesting resources, like locks, from wconfd, requesters have
to provide the name of a file they own an exclusive lock on, to prove
that they are still alive. Provide methods to obtain such a file.
"""

import fcntl
import os
import struct
import time

from alcor.utils.algo import NiceSort
from alcor import pathutils


class LiveLock(object):
  """Utility for a lockfile needed to request resources from WconfD.

  """
  def __init__(self, name=None):
    if name is None:
      name = "pid%d_" % os.getpid()
    # to avoid reusing existing lock files, extend name
    # by the current time
    name = "%s_%d" % (name, int(time.time()))
    fname = os.path.join(pathutils.LIVELOCK_DIR, name)
    self.lockfile = open(fname, 'w')

    # with LFS enabled, off_t is 64 bits even on 32-bit platforms
    try:
      os.O_LARGEFILE
      struct_flock = 'hhqqhh'
    except AttributeError:
      struct_flock = 'hhllhh'

    fcntl.fcntl(self.lockfile, fcntl.F_SETLKW,
                struct.pack(struct_flock, fcntl.F_WRLCK, 0, 0, 0, 0, 0))

  def GetPath(self):
    return self.lockfile.name

  def close(self):
    """Close the lockfile and clean it up.

    """
    self.lockfile.close()
    os.remove(self.lockfile.name)

  def __str__(self):
    return "LiveLock(" + self.GetPath() + ")"


def GuessLockfileFor(name):
  """For a given name, take the latest file matching.

  @return: the file with the latest name matching the given
      prefix in LIVELOCK_DIR, or the plain name, if none
      exists.
  """
  lockfiles = [n for n in os.listdir(pathutils.LIVELOCK_DIR)
               if n.startswith(name)]
  if len(lockfiles) > 0:
    lockfile = NiceSort(lockfiles)[-1]
  else:
    lockfile = name

  return os.path.join(pathutils.LIVELOCK_DIR, lockfile)
