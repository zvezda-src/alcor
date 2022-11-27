


"""Alcor confd client/server library

"""

from alcor import constants
from alcor import errors
from alcor import ht


_FOURCC_LEN = 4


_HTNodeDrbdItems = [ht.TString, ht.TInt, ht.TString,
                    ht.TString, ht.TString, ht.TString]
HTNodeDrbd = ht.TListOf(ht.TAnd(ht.TList, ht.TIsLength(len(_HTNodeDrbdItems)),
                                ht.TItems(_HTNodeDrbdItems)))


def PackMagic(payload):
  """Prepend the confd magic fourcc to a payload.

  """
  return b"".join([constants.CONFD_MAGIC_FOURCC_BYTES, payload])


def UnpackMagic(payload):
  """Unpack and check the confd magic fourcc from a payload.

  """
  if len(payload) < _FOURCC_LEN:
    raise errors.ConfdMagicError("UDP payload too short to contain the"
                                 " fourcc code")

  magic_number = payload[:_FOURCC_LEN]
  if magic_number != constants.CONFD_MAGIC_FOURCC_BYTES:
    raise errors.ConfdMagicError("UDP payload contains an unkown fourcc")

  return payload[_FOURCC_LEN:]
