

"""Utility functions for LVM.

"""

from alcor import constants


def CheckVolumeGroupSize(vglist, vgname, minsize):
  """Checks if the volume group list is valid.

  The function will check if a given volume group is in the list of
  volume groups and has a minimum size.

  @type vglist: dict
  @param vglist: dictionary of volume group names and their size
  @type vgname: str
  @param vgname: the volume group we should check
  @type minsize: int
  @param minsize: the minimum size we accept
  @rtype: None or str
  @return: None for success, otherwise the error message

  """
  vgsize = vglist.get(vgname, None)
  if vgsize is None:
    return "volume group '%s' missing" % vgname
  elif vgsize < minsize:
    return ("volume group '%s' too small (%s MiB required, %d MiB found)" %
            (vgname, minsize, vgsize))
  return None


def LvmExclusiveCheckNodePvs(pvs_info):
  """Check consistency of PV sizes in a node for exclusive storage.

  @type pvs_info: list
  @param pvs_info: list of L{LvmPvInfo} objects
  @rtype: tuple
  @return: A pair composed of: 1. a list of error strings describing the
    violations found, or an empty list if everything is ok; 2. a pair
    containing the sizes of the smallest and biggest PVs, in MiB.

  """
  errmsgs = []
  sizes = [pv.size for pv in pvs_info]
  # The sizes of PVs must be the same (tolerance is constants.PART_MARGIN)
  small = min(sizes)
  big = max(sizes)
  if LvmExclusiveTestBadPvSizes(small, big):
    m = ("Sizes of PVs are too different: min=%d max=%d" % (small, big))
    errmsgs.append(m)
  return (errmsgs, (small, big))


def LvmExclusiveTestBadPvSizes(small, big):
  """Test if the given PV sizes are permitted with exclusive storage.

  @param small: size of the smallest PV
  @param big: size of the biggest PV
  @return: True when the given sizes are bad, False otherwise
  """
  # Test whether no X exists such that:
  #   small >= X * (1 - constants.PART_MARGIN)  and
  #   big <= X * (1 + constants.PART_MARGIN)
  return (small * (1 + constants.PART_MARGIN) <
          big * (1 - constants.PART_MARGIN))
