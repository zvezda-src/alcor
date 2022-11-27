

"""Utility functions for managing bitarrays.

"""


from bitarray import bitarray

from alcor import errors

_AVAILABLE_SLOT = bitarray("0")


def GetFreeSlot(slots, slot=None, reserve=False):
  """Helper method to get first available slot in a bitarray

  @type slots: bitarray
  @param slots: the bitarray to operate on
  @type slot: integer
  @param slot: if given we check whether the slot is free
  @type reserve: boolean
  @param reserve: whether to reserve the first available slot or not
  @return: the idx of the (first) available slot
  @raise errors.OpPrereqError: If all slots in a bitarray are occupied
    or the given slot is not free.

  """
  if slot is not None:
    assert slot < len(slots)
    if slots[slot]:
      raise errors.GenericError("Slot %d occupied" % slot)

  else:
    avail = slots.search(_AVAILABLE_SLOT, 1)
    if not avail:
      raise errors.GenericError("All slots occupied")

    slot = int(avail[0])

  if reserve:
    slots[slot] = True

  return slot
