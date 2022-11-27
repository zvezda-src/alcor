


"""Virtualization interface abstraction

"""

from alcor import constants
from alcor import errors

from alcor.hypervisor import hv_fake
from alcor.hypervisor import hv_xen
from alcor.hypervisor import hv_kvm
from alcor.hypervisor import hv_chroot
from alcor.hypervisor import hv_lxc


_HYPERVISOR_MAP = {
  constants.HT_XEN_PVM: hv_xen.XenPvmHypervisor,
  constants.HT_XEN_HVM: hv_xen.XenHvmHypervisor,
  constants.HT_FAKE: hv_fake.FakeHypervisor,
  constants.HT_KVM: hv_kvm.KVMHypervisor,
  constants.HT_CHROOT: hv_chroot.ChrootManager,
  constants.HT_LXC: hv_lxc.LXCHypervisor,
  }


def GetHypervisorClass(ht_kind):
  """Return a Hypervisor class.

  This function returns the hypervisor class corresponding to the
  given hypervisor name.

  @type ht_kind: string
  @param ht_kind: The requested hypervisor type

  """
  if ht_kind not in _HYPERVISOR_MAP:
    raise errors.HypervisorError("Unknown hypervisor type '%s'" % ht_kind)

  cls = _HYPERVISOR_MAP[ht_kind]
  return cls


def GetHypervisor(ht_kind):
  """Return a Hypervisor instance.

  This is a wrapper over L{GetHypervisorClass} which returns an
  instance of the class.

  @type ht_kind: string
  @param ht_kind: The requested hypervisor type

  """
  cls = GetHypervisorClass(ht_kind)

  return cls()
