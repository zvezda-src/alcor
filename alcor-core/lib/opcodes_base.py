


"""OpCodes base module

This module implements part of the data structures which define the
cluster operations - the so-called opcodes.

Every operation which modifies the cluster state is expressed via
opcodes.

"""


import copy
import logging
import re

from alcor import constants
from alcor import errors
from alcor import ht
from alcor import outils


_OPID_RE = re.compile("([a-z])([A-Z])")

SUMMARY_PREFIX = {
  "CLUSTER_": "C_",
  "GROUP_": "G_",
  "NODE_": "N_",
  "INSTANCE_": "I_",
  }

DEPEND_ATTR = "depends"

COMMENT_ATTR = "comment"


def _NameComponents(name):
  """Split an opcode class name into its components

  @type name: string
  @param name: the class name, as OpXxxYyy
  @rtype: array of strings
  @return: the components of the name

  """
  assert name.startswith("Op")
  # Note: (?<=[a-z])(?=[A-Z]) would be ideal, since it wouldn't
  # consume any input, and hence we would just have all the elements
  # in the list, one by one; but it seems that split doesn't work on
  # non-consuming input, hence we have to process the input string a
  # bit
  name = _OPID_RE.sub(r"\1,\2", name)
  elems = name.split(",")
  return elems


def _NameToId(name):
  """Convert an opcode class name to an OP_ID.

  @type name: string
  @param name: the class name, as OpXxxYyy
  @rtype: string
  @return: the name in the OP_XXXX_YYYY format

  """
  if not name.startswith("Op"):
    return None
  return "_".join(n.upper() for n in _NameComponents(name))


def NameToReasonSrc(name, prefix):
  """Convert an opcode class name to a source string for the reason trail

  @type name: string
  @param name: the class name, as OpXxxYyy
  @type prefix: string
  @param prefix: the prefix that will be prepended to the opcode name
  @rtype: string
  @return: the name in the OP_XXXX_YYYY format

  """
  if not name.startswith("Op"):
    return None
  return "%s:%s" % (prefix,
                    "_".join(n.lower() for n in _NameComponents(name)))


class _AutoOpParamSlots(outils.AutoSlots):
  """Meta class for opcode definitions.

  """
  def __new__(mcs, name, bases, attrs):
    """Called when a class should be created.

    @param mcs: The meta class
    @param name: Name of created class
    @param bases: Base classes
    @type attrs: dict
    @param attrs: Class attributes

    """
    assert "OP_ID" not in attrs, "Class '%s' defining OP_ID" % name

    slots = mcs._GetSlots(attrs)
    assert "OP_DSC_FIELD" not in attrs or attrs["OP_DSC_FIELD"] in slots, \
      "Class '%s' uses unknown field in OP_DSC_FIELD" % name
    assert ("OP_DSC_FORMATTER" not in attrs or
            callable(attrs["OP_DSC_FORMATTER"])), \
      ("Class '%s' uses non-callable in OP_DSC_FORMATTER (%s)" %
       (name, type(attrs["OP_DSC_FORMATTER"])))

    attrs["OP_ID"] = _NameToId(name)

    # pylint: disable=E1121
    return outils.AutoSlots.__new__(mcs, name, bases, attrs)

  @classmethod
  def _GetSlots(mcs, attrs):
    """Build the slots out of OP_PARAMS.

    """
    # Always set OP_PARAMS to avoid duplicates in BaseOpCode.GetAllParams
    params = attrs.setdefault("OP_PARAMS", [])

    # Use parameter names as slots
    return [pname for (pname, _, _, _) in params]


class BaseOpCode(outils.ValidatedSlots, metaclass=_AutoOpParamSlots):
  """A simple serializable object.

  This object serves as a parent class for OpCode without any custom
  field handling.

  """

  def __init__(self, **kwargs):
    outils.ValidatedSlots.__init__(self, **kwargs)
    for key, default, _, _ in self.__class__.GetAllParams():
      if not hasattr(self, key):
        setattr(self, key, default)

  def __getstate__(self):
    """Generic serializer.

    This method just returns the contents of the instance as a
    dictionary.

    @rtype:  C{dict}
    @return: the instance attributes and their values

    """
    state = {}
    for name in self.GetAllSlots():
      if hasattr(self, name):
        state[name] = getattr(self, name)
    return state

  def __setstate__(self, state):
    """Generic unserializer.

    This method just restores from the serialized state the attributes
    of the current instance.

    @param state: the serialized opcode data
    @type state:  C{dict}

    """
    if not isinstance(state, dict):
      raise ValueError("Invalid data to __setstate__: expected dict, got %s" %
                       type(state))

    for name in self.GetAllSlots():
      if name not in state and hasattr(self, name):
        delattr(self, name)

    for name in state:
      setattr(self, name, state[name])

  @classmethod
  def GetAllParams(cls):
    """Compute list of all parameters for an opcode.

    """
    slots = []
    for parent in cls.__mro__:
      slots.extend(getattr(parent, "OP_PARAMS", []))
    return slots

  def Validate(self, set_defaults): # pylint: disable=W0221
    """Validate opcode parameters, optionally setting default values.

    @type set_defaults: bool
    @param set_defaults: whether to set default values

    @rtype: NoneType
    @return: L{None}, if the validation succeeds
    @raise errors.OpPrereqError: when a parameter value doesn't match
                                 requirements

    """
    for (attr_name, default, test, _) in self.GetAllParams():
      assert callable(test)

      if hasattr(self, attr_name):
        attr_val = getattr(self, attr_name)
      else:
        attr_val = copy.deepcopy(default)

      if test(attr_val):
        if set_defaults:
          setattr(self, attr_name, attr_val)
      elif ht.TInt(attr_val) and test(float(attr_val)):
        if set_defaults:
          setattr(self, attr_name, float(attr_val))
      else:
        op_id = self.OP_ID # pylint: disable=E1101
        logging.error("OpCode %s, parameter %s, has invalid type %s/value"
                      " '%s' expecting type %s",
                      op_id, attr_name, type(attr_val), attr_val, test)

        if attr_val is None:
          logging.error("OpCode %s, parameter %s, has default value None which"
                        " is does not check against the parameter's type: this"
                        " means this parameter is required but no value was"
                        " given",
                        op_id, attr_name)

        raise errors.OpPrereqError("Parameter '%s.%s' fails validation" %
                                   (op_id, attr_name),
                                   errors.ECODE_INVAL)


def BuildJobDepCheck(relative):
  """Builds check for job dependencies (L{DEPEND_ATTR}).

  @type relative: bool
  @param relative: Whether to accept relative job IDs (negative)
  @rtype: callable

  """
  if relative:
    job_id = ht.TOr(ht.TJobId, ht.TRelativeJobId)
  else:
    job_id = ht.TJobId

  job_dep = \
    ht.TAnd(ht.TOr(ht.TListOf(ht.TAny), ht.TTuple),
            ht.TIsLength(2),
            ht.TItems([job_id,
                       ht.TListOf(ht.TElemOf(constants.JOBS_FINALIZED))]))

  return ht.TMaybe(ht.TListOf(job_dep))


TNoRelativeJobDependencies = BuildJobDepCheck(False)
