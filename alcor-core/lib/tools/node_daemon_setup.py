

"""Script to configure the node daemon.

"""

import os
import os.path
import optparse
import sys
import logging

from alcor import cli
from alcor import constants
from alcor import errors
from alcor import pathutils
from alcor import utils
from alcor import runtime
from alcor import ht
from alcor import ssconf
from alcor.tools import common


_DATA_CHECK = ht.TStrictDict(False, True, {
  constants.NDS_CLUSTER_NAME: ht.TNonEmptyString,
  constants.NDS_NODE_DAEMON_CERTIFICATE: ht.TNonEmptyString,
  constants.NDS_HMAC: ht.TNonEmptyString,
  constants.NDS_SSCONF: ht.TDictOf(ht.TNonEmptyString, ht.TString),
  constants.NDS_START_NODE_DAEMON: ht.TBool,
  constants.NDS_NODE_NAME: ht.TString,
  })


class SetupError(errors.GenericError):
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

  return VerifyOptions(parser, opts, args)


def VerifyOptions(parser, opts, args):
  """Verifies options and arguments for correctness.

  """
  if args:
    parser.error("No arguments are expected")

  return opts


def VerifySsconf(data, cluster_name, _verify_fn=ssconf.VerifyKeys):
  """Verifies ssconf names.

  @type data: dict

  """
  items = data.get(constants.NDS_SSCONF)

  if not items:
    raise SetupError("Ssconf values must be specified")

  # TODO: Should all keys be required? Right now any subset of valid keys is
  # accepted.
  _verify_fn(list(items))

  if items.get(constants.SS_CLUSTER_NAME) != cluster_name:
    raise SetupError("Cluster name in ssconf does not match")

  return items


def Main():
  """Main routine.

  """
  opts = ParseOptions()

  utils.SetupToolLogging(opts.debug, opts.verbose)

  try:
    getent = runtime.GetEnts()

    data = common.LoadData(sys.stdin.read(), SetupError)

    cluster_name = common.VerifyClusterName(data, SetupError,
                                            constants.NDS_CLUSTER_NAME)
    cert_pem = common.VerifyCertificateStrong(data, SetupError)
    hmac_key = common.VerifyHmac(data, SetupError)
    ssdata = VerifySsconf(data, cluster_name)

    logging.info("Writing ssconf files ...")
    ssconf.WriteSsconfFiles(ssdata, dry_run=opts.dry_run)

    logging.info("Writing hmac.key ...")
    utils.WriteFile(pathutils.CONFD_HMAC_KEY, data=hmac_key,
                    mode=pathutils.NODED_CERT_MODE,
                    uid=getent.masterd_uid, gid=getent.masterd_gid,
                    dry_run=opts.dry_run)

    logging.info("Writing node daemon certificate ...")
    utils.WriteFile(pathutils.NODED_CERT_FILE, data=cert_pem,
                    mode=pathutils.NODED_CERT_MODE,
                    uid=getent.masterd_uid, gid=getent.masterd_gid,
                    dry_run=opts.dry_run)
    common.GenerateClientCertificate(data, SetupError)

    if (data.get(constants.NDS_START_NODE_DAEMON) and # pylint: disable=E1103
        not opts.dry_run):
      logging.info("Restarting node daemon ...")

      stop_cmd = "%s stop-all" % pathutils.DAEMON_UTIL
      noded_cmd = "%s start %s" % (pathutils.DAEMON_UTIL, constants.NODED)
      mond_cmd = ""
      if constants.ENABLE_MOND:
        mond_cmd = "%s start %s" % (pathutils.DAEMON_UTIL, constants.MOND)

      cmd = "; ".join([stop_cmd, noded_cmd, mond_cmd])

      result = utils.RunCmd(cmd, interactive=True)
      if result.failed:
        raise SetupError("Could not start the node daemons, command '%s'"
                         " failed: %s" % (result.cmd, result.fail_reason))

    logging.info("Node daemon successfully configured")
  except Exception as err: # pylint: disable=W0703
    logging.debug("Caught unhandled exception", exc_info=True)

    (retcode, message) = cli.FormatError(err)
    logging.error(message)

    return retcode
  else:
    return constants.EXIT_SUCCESS
