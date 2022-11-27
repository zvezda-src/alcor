


"""Reserve resources, so that jobs can't take them.

"""

from alcor import errors


class TemporaryReservationManager(object):
  """A temporary resource reservation manager.

  This is used to reserve resources in a job, before using them, making sure
  other jobs cannot get them in the meantime.

  """
  def __init__(self):
    self._ec_reserved = {}

  def Reserved(self, resource):
    for holder_reserved in self._ec_reserved.values():
      if resource in holder_reserved:
        return True
    return False

  def Reserve(self, ec_id, resource):
    if self.Reserved(resource):
      raise errors.ReservationError("Duplicate reservation for resource '%s'"
                                    % str(resource))
    if ec_id not in self._ec_reserved:
      self._ec_reserved[ec_id] = set([resource])
    else:
      self._ec_reserved[ec_id].add(resource)

  def DropECReservations(self, ec_id):
    if ec_id in self._ec_reserved:
      del self._ec_reserved[ec_id]

  def GetReserved(self):
    all_reserved = set()
    for holder_reserved in self._ec_reserved.values():
      all_reserved.update(holder_reserved)
    return all_reserved

  def GetECReserved(self, ec_id):
    """ Used when you want to retrieve all reservations for a specific
        execution context. E.g when commiting reserved IPs for a specific
        network.

    """
    ec_reserved = set()
    if ec_id in self._ec_reserved:
      ec_reserved.update(self._ec_reserved[ec_id])
    return ec_reserved

  def Generate(self, existing, generate_one_fn, ec_id):
    """Generate a new resource of this type

    """
    assert callable(generate_one_fn)

    all_elems = self.GetReserved()
    all_elems.update(existing)
    retries = 64
    while retries > 0:
      new_resource = generate_one_fn()
      if new_resource is not None and new_resource not in all_elems:
        break
    else:
      raise errors.ConfigurationError("Not able generate new resource"
                                      " (last tried: %s)" % new_resource)
    self.Reserve(ec_id, new_resource)
    return new_resource
