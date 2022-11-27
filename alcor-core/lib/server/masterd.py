


"""Master daemon program.

Some classes deviates from the standard style guide since the
inheritance from parent classes requires it.

"""


import logging

from alcor import config
from alcor import constants
from alcor import jqueue
from alcor import utils
import alcor.rpc.node as rpc


CLIENT_REQUEST_WORKERS = 16

EXIT_NOTMASTER = constants.EXIT_NOTMASTER
EXIT_NODESETUP_ERROR = constants.EXIT_NODESETUP_ERROR


class AlcorContext(object):
  """Context common to all alcor threads.

  This class creates and holds common objects shared by all threads.

  """
  # pylint: disable=W0212
  # we do want to ensure a singleton here
  _instance = None

  def __init__(self, livelock=None):
    """Constructs a new AlcorContext object.

    There should be only a AlcorContext object at any time, so this
    function raises an error if this is not the case.

    """
    assert self.__class__._instance is None, "double AlcorContext instance"

    # Create a livelock file
    if livelock is None:
      self.livelock = utils.livelock.LiveLock("masterd")
    else:
      self.livelock = livelock

    # Job queue
    cfg = self.GetConfig(None)
    logging.debug("Creating the job queue")
    self.jobqueue = jqueue.JobQueue(self, cfg)

    # setting this also locks the class against attribute modifications
    self.__class__._instance = self

  def __setattr__(self, name, value):
    """Setting AlcorContext attributes is forbidden after initialization.

    """
    assert self.__class__._instance is None, "Attempt to modify Alcor Context"
    object.__setattr__(self, name, value)

  def GetWConfdContext(self, ec_id):
    return config.GetWConfdContext(ec_id, self.livelock)

  def GetConfig(self, ec_id):
    return config.GetConfig(ec_id, self.livelock)

  # pylint: disable=R0201
  # method could be a function, but keep interface backwards compatible
  def GetRpc(self, cfg):
    return rpc.RpcRunner(cfg, lambda _: None)

  def AddNode(self, cfg, node, ec_id):
    """Adds a node to the configuration.

    """
    # Add it to the configuration
    cfg.AddNode(node, ec_id)

  def RemoveNode(self, cfg, node):
    """Removes a node from the configuration and lock manager.

    """
    # Remove node from configuration
    cfg.RemoveNode(node.uuid)
