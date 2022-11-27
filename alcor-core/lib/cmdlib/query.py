


"""Logical units for queries."""

from alcor import constants
from alcor import errors
from alcor import query
from alcor.cmdlib.base import NoHooksLU
from alcor.cmdlib.cluster import ClusterQuery
from alcor.cmdlib.misc import ExtStorageQuery
from alcor.cmdlib.operating_system import OsQuery


_QUERY_IMPL = {
  constants.QR_CLUSTER: ClusterQuery,
  constants.QR_OS: OsQuery,
  constants.QR_EXTSTORAGE: ExtStorageQuery,
  }

assert set(_QUERY_IMPL.keys()) == constants.QR_VIA_OP


def _GetQueryImplementation(name):
  """Returns the implementation for a query type.

  @param name: Query type, must be one of L{constants.QR_VIA_OP}

  """
  try:
    return _QUERY_IMPL[name]
  except KeyError:
    raise errors.OpPrereqError("Unknown query resource '%s'" % name,
                               errors.ECODE_INVAL)


class LUQuery(NoHooksLU):
  """Query for resources/items of a certain kind.

  """
  REQ_BGL = False

  def CheckArguments(self):
    qcls = _GetQueryImplementation(self.op.what)

    self.impl = qcls(self.op.qfilter, self.op.fields, self.op.use_locking)

  def ExpandNames(self):
    self.impl.ExpandNames(self)

  def DeclareLocks(self, level):
    self.impl.DeclareLocks(self, level)

  def Exec(self, feedback_fn):
    return self.impl.NewStyleQuery(self)


class LUQueryFields(NoHooksLU):
  """Query for resources/items of a certain kind.

  """
  REQ_BGL = False

  def CheckArguments(self):
    self.qcls = _GetQueryImplementation(self.op.what)

  def ExpandNames(self):
    self.needed_locks = {}

  def Exec(self, feedback_fn):
    return query.QueryFields(self.qcls.FIELDS, self.op.fields)
