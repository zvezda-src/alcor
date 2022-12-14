

"""Module implementing configuration details at runtime.

"""


import grp
import pwd
import threading
import platform

from alcor import constants
from alcor import errors
from alcor import luxi
from alcor.rpc.errors import NoMasterError
from alcor import pathutils
from alcor import ssconf
from alcor import utils


_priv = None
_priv_lock = threading.Lock()

_arch = None


def GetUid(user, _getpwnam):
  """Retrieve the uid from the database.

  @type user: string
  @param user: The username to retrieve
  @return: The resolved uid

  """
  try:
    return _getpwnam(user).pw_uid
  except KeyError as err:
    raise errors.ConfigurationError("User '%s' not found (%s)" % (user, err))


def GetGid(group, _getgrnam):
  """Retrieve the gid from the database.

  @type group: string
  @param group: The group name to retrieve
  @return: The resolved gid

  """
  try:
    return _getgrnam(group).gr_gid
  except KeyError as err:
    raise errors.ConfigurationError("Group '%s' not found (%s)" % (group, err))


class GetentResolver(object):
  """Resolves Alcor uids and gids by name.

  @ivar masterd_uid: The resolved uid of the masterd user
  @ivar masterd_gid: The resolved gid of the masterd group
  @ivar confd_uid: The resolved uid of the confd user
  @ivar confd_gid: The resolved gid of the confd group
  @ivar wconfd_uid: The resolved uid of the wconfd user
  @ivar wconfd_gid: The resolved gid of the wconfd group
  @ivar luxid_uid: The resolved uid of the luxid user
  @ivar luxid_gid: The resolved gid of the luxid group
  @ivar rapi_uid: The resolved uid of the rapi user
  @ivar rapi_gid: The resolved gid of the rapi group
  @ivar noded_uid: The resolved uid of the noded user
  @ivar noded_gid: The resolved uid of the noded group
  @ivar mond_uid: The resolved uid of the mond user
  @ivar mond_gid: The resolved gid of the mond group
  @ivar metad_uid: The resolved uid of the metad user
  @ivar metad_gid: The resolved gid of the metad group
  @ivar daemons_gid: The resolved gid of the daemons group
  @ivar admin_gid: The resolved gid of the admin group

  """
  def __init__(self, _getpwnam=pwd.getpwnam, _getgrnam=grp.getgrnam):
    """Initialize the resolver.

    """
    # Daemon pairs
    self.masterd_uid = GetUid(constants.MASTERD_USER, _getpwnam)
    self.masterd_gid = GetGid(constants.MASTERD_GROUP, _getgrnam)

    self.confd_uid = GetUid(constants.CONFD_USER, _getpwnam)
    self.confd_gid = GetGid(constants.CONFD_GROUP, _getgrnam)

    self.wconfd_uid = GetUid(constants.WCONFD_USER, _getpwnam)
    self.wconfd_gid = GetGid(constants.WCONFD_GROUP, _getgrnam)

    self.luxid_uid = GetUid(constants.LUXID_USER, _getpwnam)
    self.luxid_gid = GetGid(constants.LUXID_GROUP, _getgrnam)

    self.rapi_uid = GetUid(constants.RAPI_USER, _getpwnam)
    self.rapi_gid = GetGid(constants.RAPI_GROUP, _getgrnam)

    self.noded_uid = GetUid(constants.NODED_USER, _getpwnam)
    self.noded_gid = GetGid(constants.NODED_GROUP, _getgrnam)

    self.mond_uid = GetUid(constants.MOND_USER, _getpwnam)
    self.mond_gid = GetGid(constants.MOND_GROUP, _getgrnam)

    self.metad_uid = GetUid(constants.METAD_USER, _getpwnam)
    self.metad_gid = GetGid(constants.METAD_GROUP, _getgrnam)

    # Misc Alcor groups
    self.daemons_gid = GetGid(constants.DAEMONS_GROUP, _getgrnam)
    self.admin_gid = GetGid(constants.ADMIN_GROUP, _getgrnam)

    self._uid2user = {
      self.masterd_uid: constants.MASTERD_USER,
      self.confd_uid: constants.CONFD_USER,
      self.wconfd_uid: constants.WCONFD_USER,
      self.luxid_uid: constants.LUXID_USER,
      self.rapi_uid: constants.RAPI_USER,
      self.noded_uid: constants.NODED_USER,
      self.metad_uid: constants.METAD_USER,
      self.mond_uid: constants.MOND_USER,
      }

    self._gid2group = {
      self.masterd_gid: constants.MASTERD_GROUP,
      self.confd_gid: constants.CONFD_GROUP,
      self.wconfd_gid: constants.WCONFD_GROUP,
      self.luxid_gid: constants.LUXID_GROUP,
      self.rapi_gid: constants.RAPI_GROUP,
      self.noded_gid: constants.NODED_GROUP,
      self.mond_gid: constants.MOND_GROUP,
      self.metad_gid: constants.METAD_GROUP,
      self.daemons_gid: constants.DAEMONS_GROUP,
      self.admin_gid: constants.ADMIN_GROUP,
      }

    self._user2uid = utils.InvertDict(self._uid2user)
    self._group2gid = utils.InvertDict(self._gid2group)

  def LookupUid(self, uid):
    """Looks which Alcor user belongs to this uid.

    @param uid: The uid to lookup
    @returns The user name associated with that uid

    """
    try:
      return self._uid2user[uid]
    except KeyError:
      raise errors.ConfigurationError("Unknown Alcor uid '%d'" % uid)

  def LookupGid(self, gid):
    """Looks which Alcor group belongs to this gid.

    @param gid: The gid to lookup
    @returns The group name associated with that gid

    """
    try:
      return self._gid2group[gid]
    except KeyError:
      raise errors.ConfigurationError("Unknown Alcor gid '%d'" % gid)

  def LookupUser(self, name):
    """Looks which uid belongs to this name.

    @param name: The name to lookup
    @returns The uid associated with that user name

    """
    try:
      return self._user2uid[name]
    except KeyError:
      raise errors.ConfigurationError("Unknown Alcor user '%s'" % name)

  def LookupGroup(self, name):
    """Looks which gid belongs to this name.

    @param name: The name to lookup
    @returns The gid associated with that group name

    """
    try:
      return self._group2gid[name]
    except KeyError:
      raise errors.ConfigurationError("Unknown Alcor group '%s'" % name)


def GetEnts(resolver=GetentResolver):
  """Singleton wrapper around resolver instance.

  As this method is accessed by multiple threads at the same time
  we need to take thread-safety carefully.

  """
  # We need to use the global keyword here
  global _priv # pylint: disable=W0603

  if not _priv:
    _priv_lock.acquire()
    try:
      if not _priv:
        # W0621: Redefine '_priv' from outer scope (used for singleton)
        _priv = resolver() # pylint: disable=W0621
    finally:
      _priv_lock.release()

  return _priv


def InitArchInfo():
  """Initialize architecture information.

  We can assume this information never changes during the lifetime of a
  process, therefore the information can easily be cached.

  @note: This function uses C{platform.architecture} to retrieve the Python
    binary architecture and does so by forking to run C{file} (see Python
    documentation for more information). Therefore it must not be used in a
    multi-threaded environment.

  """
  global _arch # pylint: disable=W0603

  if _arch is not None:
    raise errors.ProgrammerError("Architecture information can only be"
                                 " initialized once")

  _arch = (platform.architecture()[0], platform.machine())


def GetArchInfo():
  """Returns previsouly initialized architecture information.

  """
  if _arch is None:
    raise errors.ProgrammerError("Architecture information hasn't been"
                                 " initialized")

  return _arch


def GetClient():
  """Connects to the a luxi socket and returns a client.

  """
  try:
    client = luxi.Client(address=pathutils.QUERY_SOCKET)
  except NoMasterError:
    ss = ssconf.SimpleStore()

    # Try to read ssconf file
    try:
      ss.GetMasterNode()
    except errors.ConfigurationError:
      raise errors.OpPrereqError("Cluster not initialized or this machine is"
                                 " not part of a cluster",
                                 errors.ECODE_INVAL)

    master, myself = ssconf.GetMasterAndMyself(ss=ss)
    if master != myself:
      raise errors.OpPrereqError("This is not the master node, please connect"
                                 " to node '%s' and rerun the command" %
                                 master, errors.ECODE_INVAL)
    raise
  return client
