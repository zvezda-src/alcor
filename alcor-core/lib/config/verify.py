


"""Verification helpers for the configuration object."""

from alcor import constants
from alcor import errors
from alcor import objects
from alcor import utils


def ValidateConfig(data):
  """Verifies that a configuration dict looks valid.

  This only verifies the version of the configuration.

  @raise errors.ConfigurationError: if the version differs from what
      we expect

  """
  if data['version'] != constants.CONFIG_VERSION:
    raise errors.ConfigVersionMismatch(constants.CONFIG_VERSION,
                                       data['version'])


def VerifyType(owner, attr, value, template, callback):
  """Checks if an attribute has correct form.

  @type owner: str
  @param owner: name of the object containing the attribute
  @type attr: str
  @param attr: name of the attribute
  @type value: dict
  @param value: actual value of the attribute
  @type template: dict
  @param template: expected types of the keys
  @type callback: callable
  @param callback: will be called if there is an error

  """
  try:
    utils.ForceDictType(value, template)
  except errors.GenericError as err:
    return callback("%s has invalid %s: %s" % (owner, attr, err))


def VerifyNic(owner, params, callback):
  """Checks if a NIC has correct form.

  @type owner: str
  @param owner: name of the object containing the attribute
  @type params: dict
  @param params: actual value of the NIC parameters
  @type callback: callable
  @param callback: will be called if there is an error

  """
  try:
    objects.NIC.CheckParameterSyntax(params)
  except errors.ConfigurationError as err:
    callback("%s has invalid nicparams: %s" % (owner, err))


def VerifyIpolicy(owner, ipolicy, iscluster, callback):
  """Checks if an ipolicy has correct form.

  @type owner: str
  @param owner: name of the object containing the attribute
  @type ipolicy: dict
  @param ipolicy: actual value of the ipolicy parameters
  @type iscluster: bool
  @param iscluster: True iff the owner is the cluster
  @type callback: callable
  @param callback: will be called if there is an error

  """
  try:
    objects.InstancePolicy.CheckParameterSyntax(ipolicy, iscluster)
  except errors.ConfigurationError as err:
    callback("%s has invalid instance policy: %s" % (owner, err))
  for key, value in ipolicy.items():
    if key == constants.ISPECS_MINMAX:
      for i, val in enumerate(value):
        VerifyIspecs(owner, "ipolicy/%s[%s]" % (key, i), val, callback)
    elif key == constants.ISPECS_STD:
      VerifyType(owner, "ipolicy/" + key, value,
                 constants.ISPECS_PARAMETER_TYPES, callback)
    else:
      # FIXME: assuming list type
      if key in constants.IPOLICY_PARAMETERS:
        exp_type = float
        # if the value is int, it can be converted into float
        convertible_types = [int]
      else:
        exp_type = list
        convertible_types = []
        # Try to convert from allowed types, if necessary.
        if any(isinstance(value, ct) for ct in convertible_types):
          try:
            value = exp_type(value)
            ipolicy[key] = value
          except ValueError:
            pass
        if not isinstance(value, exp_type):
          callback("%s has invalid instance policy: for %s,"
                   " expecting %s, got %s" %
                   (owner, key, exp_type.__name__, type(value)))


def VerifyIspecs(owner, parentkey, params, callback):
  """Checks if an ispec has correct form.

  @type owner: str
  @param owner: name of the object containing the attribute
  @type parentkey: str
  @param parentkey: the root name of the key
  @type params: dict
  @param params: actual value of the ispec parameters
  @type callback: callable
  @param callback: will be called if there is an error

  """
  for (key, value) in params.items():
    fullkey = "/".join([parentkey, key])
    VerifyType(owner, fullkey, value, constants.ISPECS_PARAMETER_TYPES,
               callback)
