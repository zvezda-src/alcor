

"""Script to recreate and sign the client SSL certificates.

"""

import os
import os.path
import optparse
import sys
import logging

from alcor import cli
from alcor import constants
from alcor import errors
from alcor import utils
from alcor import ht
from alcor import pathutils
from alcor.tools import common


_DATA_CHECK = ht.TStrictDict(False, True, {
  constants.NDS_CLUSTER_NAME: ht.TNonEmptyString,
  constants.NDS_NODE_DAEMON_CERTIFICATE: ht.TNonEmptyString,
  constants.NDS_NODE_NAME: ht.TNonEmptyString,
  constants.NDS_ACTION: ht.TNonEmptyString,
  })


class SslSetupError(errors.GenericError):
  """Local class for reporting errors.

  """


def ParseOptions():
  """Parses the options passed to the program.

  @return: Options and arguments

  """
  parser = optparse.OptionParser(usage="%prog [--dry-run]",
                                 prog=os.path.basename(sys.argv[0]))
  parser.add_option(cli.DEBUG_OPT)
  parser.add_option(cli.VERBOSE_OPT)
  parser.add_option(cli.DRY_RUN_OPT)

  (opts, args) = parser.parse_args()

  return common.VerifyOptions(parser, opts, args)


def DeleteClientCertificate():
  """Deleting the client certificate. This is necessary for downgrades."""
  if os.path.exists(pathutils.NODED_CLIENT_CERT_FILE):
    os.remove(pathutils.NODED_CLIENT_CERT_FILE)
  else:
    logging.debug("Trying to delete the client certificate '%s' which did not"
                  " exist.", pathutils.NODED_CLIENT_CERT_FILE)


def ClearMasterCandidateSsconfList():
  """Clear the ssconf list of master candidate certs.

  This is necessary when deleting the client certificates for a downgrade,
  because otherwise the master cannot distribute the configuration to the
  nodes via RPC during a downgrade anymore.

  """
  ssconf_file = os.path.join(
    pathutils.DATA_DIR,
    "%s%s" % (constants.SSCONF_FILEPREFIX,
              constants.SS_MASTER_CANDIDATES_CERTS))
  if os.path.exists:
    os.remove(ssconf_file)
  else:
    logging.debug("Trying to delete the ssconf file '%s' which does not"
                  " exist.", ssconf_file)


def Main():
  """Main routine.

  """
  opts = ParseOptions()

  utils.SetupToolLogging(opts.debug, opts.verbose)

  try:
    data = common.LoadData(sys.stdin.read(), _DATA_CHECK)

    common.VerifyClusterName(data, SslSetupError, constants.NDS_CLUSTER_NAME)

    # Verifies whether the server certificate of the caller
    # is the same as on this node.
    common.VerifyCertificateStrong(data, SslSetupError)

    action = data.get(constants.NDS_ACTION)
    if not action:
      raise SslSetupError("No Action specified.")

    if action == constants.CRYPTO_ACTION_CREATE:
      common.GenerateClientCertificate(data, SslSetupError)
    elif action == constants.CRYPTO_ACTION_DELETE:
      DeleteClientCertificate()
      ClearMasterCandidateSsconfList()
    else:
      raise SslSetupError("Unsupported action: %s." % action)

  except Exception as err: # pylint: disable=W0703
    logging.debug("Caught unhandled exception", exc_info=True)

    (retcode, message) = cli.FormatError(err)
    logging.error(message)

    return retcode
  else:
    return constants.EXIT_SUCCESS
