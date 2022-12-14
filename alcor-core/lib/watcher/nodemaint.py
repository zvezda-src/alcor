


"""Module doing node maintenance for Alcor watcher.

"""

import logging

from alcor import constants
from alcor import errors
from alcor import hypervisor
from alcor import netutils
from alcor import ssconf
from alcor import utils
from alcor import confd
from alcor.storage import drbd

import alcor.confd.client # pylint: disable=W0611


class NodeMaintenance(object):
  """Talks to confd daemons and possible shutdown instances/drbd devices.

  """
  def __init__(self):
    self.store_cb = confd.client.StoreResultCallback()
    self.filter_cb = confd.client.ConfdFilterCallback(self.store_cb)
    self.confd_client = confd.client.GetConfdClient(self.filter_cb)

  @staticmethod
  def ShouldRun():
    """Checks whether node maintenance should run.

    """
    try:
      return ssconf.SimpleStore().GetMaintainNodeHealth()
    except errors.ConfigurationError as err:
      logging.error("Configuration error, not activating node maintenance: %s",
                    err)
      return False

  @staticmethod
  def GetRunningInstances():
    """Compute list of hypervisor/running instances.

    """
    hyp_list = ssconf.SimpleStore().GetHypervisorList()
    hvparams = ssconf.SimpleStore().GetHvparams()
    results = []
    for hv_name in hyp_list:
      try:
        hv = hypervisor.GetHypervisor(hv_name)
        ilist = hv.ListInstances(hvparams=hvparams)
        results.extend([(iname, hv_name) for iname in ilist])
      except: # pylint: disable=W0702
        logging.error("Error while listing instances for hypervisor %s",
                      hv_name, exc_info=True)
    return results

  @staticmethod
  def GetUsedDRBDs():
    """Get list of used DRBD minors.

    """
    return drbd.DRBD8.GetUsedDevs()

  @classmethod
  def DoMaintenance(cls, role):
    """Maintain the instance list.

    """
    if role == constants.CONFD_NODE_ROLE_OFFLINE:
      inst_running = cls.GetRunningInstances()
      cls.ShutdownInstances(inst_running)
      drbd_running = cls.GetUsedDRBDs()
      cls.ShutdownDRBD(drbd_running)
    else:
      logging.debug("Not doing anything for role %s", role)

  @staticmethod
  def ShutdownInstances(inst_running):
    """Shutdown running instances.

    """
    names_running = set([i[0] for i in inst_running])
    if names_running:
      logging.info("Following instances should not be running,"
                   " shutting them down: %s", utils.CommaJoin(names_running))
      # this dictionary will collapse duplicate instance names (only
      # xen pvm/vhm) into a single key, which is fine
      i2h = dict(inst_running)
      for name in names_running:
        hv_name = i2h[name]
        hv = hypervisor.GetHypervisor(hv_name)
        hv.StopInstance(None, force=True, name=name)

  @staticmethod
  def ShutdownDRBD(drbd_running):
    """Shutdown active DRBD devices.

    """
    if drbd_running:
      logging.info("Following DRBD minors should not be active,"
                   " shutting them down: %s", utils.CommaJoin(drbd_running))
      for minor in drbd_running:
        drbd.DRBD8.ShutdownAll(minor)

  def Exec(self):
    """Check node status versus cluster desired state.

    """
    my_name = netutils.Hostname.GetSysName()
    req = \
      confd.client.ConfdClientRequest(type=constants.CONFD_REQ_NODE_ROLE_BYNAME,
                                      query=my_name)
    self.confd_client.SendRequest(req, async_=False, coverage=-1)
    timed_out, _, _ = self.confd_client.WaitForReply(req.rsalt)
    if not timed_out:
      # should have a valid response
      status, result = self.store_cb.GetResponse(req.rsalt)
      assert status, "Missing result but received replies"
      if not self.filter_cb.consistent[req.rsalt]:
        logging.warning("Inconsistent replies, not doing anything")
        return
      self.DoMaintenance(result.server_reply.answer)
    else:
      logging.warning("Confd query timed out, cannot do maintenance actions")
