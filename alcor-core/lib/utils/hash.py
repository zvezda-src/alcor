

"""Utility functions for hashing.

"""

import os
import hmac

from hashlib import sha1

from alcor import compat


def Sha1Hmac(key, msg, salt=None):
  """Calculates the HMAC-SHA1 digest of a message.

  HMAC is defined in RFC2104.

  @type key: string
  @param key: Secret key
  @type msg: string or bytes

  """
  key = key.encode("utf-8")

  if isinstance(msg, str):
    msg = msg.encode("utf-8")

  if salt:
    salt = salt.encode("utf-8")
    salted_msg = salt + msg
  else:
    salted_msg = msg

  return hmac.new(key, salted_msg, sha1).hexdigest()


def VerifySha1Hmac(key, text, digest, salt=None):
  """Verifies the HMAC-SHA1 digest of a text.

  HMAC is defined in RFC2104.

  @type key: string
  @param key: Secret key
  @type text: string
  @type digest: string
  @param digest: Expected digest
  @rtype: bool
  @return: Whether HMAC-SHA1 digest matches

  """
  return digest.lower() == Sha1Hmac(key, text, salt=salt).lower()


def _FingerprintFile(filename):
  """Compute the fingerprint of a file.

  If the file does not exist, a None will be returned
  instead.

  @type filename: str
  @param filename: the filename to checksum
  @rtype: str
  @return: the hex digest of the sha checksum of the contents
      of the file

  """
  if not (os.path.exists(filename) and os.path.isfile(filename)):
    return None

  fp = sha1()

  with open(filename, "rb") as f:
    while True:
      data = f.read(4096)
      if not data:
        break

      fp.update(data)

  return fp.hexdigest()


def FingerprintFiles(files):
  """Compute fingerprints for a list of files.

  @type files: list
  @param files: the list of filename to fingerprint
  @rtype: dict
  @return: a dictionary filename: fingerprint, holding only
      existing files

  """
  ret = {}

  for filename in files:
    cksum = _FingerprintFile(filename)
    if cksum:
      ret[filename] = cksum

  return ret
