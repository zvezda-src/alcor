

"""Alcor RAPI module"""

from alcor import compat


RAPI_ACCESS_WRITE = "write"
RAPI_ACCESS_READ = "read"

RAPI_ACCESS_ALL = compat.UniqueFrozenset([
  RAPI_ACCESS_WRITE,
  RAPI_ACCESS_READ,
  ])
