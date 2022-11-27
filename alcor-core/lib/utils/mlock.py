

"""Wrapper around mlockall(2).

"""

import os
import logging

from alcor import errors

try:
  # pylint: disable=F0401
  import ctypes
except ImportError:
  ctypes = None


_MCL_CURRENT = 1
_MCL_FUTURE = 2


def Mlockall(_ctypes=ctypes):
  """Lock current process' virtual address space into RAM.

  This is equivalent to the C call C{mlockall(MCL_CURRENT | MCL_FUTURE)}. See
  mlockall(2) for more details. This function requires the C{ctypes} module.

  @raises errors.NoCtypesError: If the C{ctypes} module is not found

  """
  if _ctypes is None:
    raise errors.NoCtypesError()

  try:
    libc = _ctypes.cdll.LoadLibrary("libc.so.6")
  except EnvironmentError as err:
    logging.error("Failure trying to load libc: %s", err)
    libc = None
  if libc is None:
    logging.error("Cannot set memory lock, ctypes cannot load libc")
    return

  # The ctypes module before Python 2.6 does not have built-in functionality to
  # access the global errno global (which, depending on the libc and build
  # options, is per thread), where function error codes are stored. Use GNU
  # libc's way to retrieve errno(3) instead, which is to use the pointer named
  # "__errno_location" (see errno.h and bits/errno.h).
  # pylint: disable=W0212
  libc.__errno_location.restype = _ctypes.POINTER(_ctypes.c_int)

  if libc.mlockall(_MCL_CURRENT | _MCL_FUTURE):
    # pylint: disable=W0212
    logging.error("Cannot set memory lock: %s",
                  os.strerror(libc.__errno_location().contents.value))
    return

  logging.debug("Memory lock set")
