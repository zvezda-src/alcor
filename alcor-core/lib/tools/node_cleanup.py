

"""Script to configure the node daemon.

"""

import os
import os.path
import optparse
import sys
import logging

from alcor import cli
from alcor import constants
from alcor import pathutils
from alcor import ssconf
from alcor import utils


def ParseOptions():
  """Parses the options passed to the program.

  @return: Options and arguments

  """
  parser = optparse.OptionParser(usage="%prog [--no-backup]",
                                 prog=os.path.basename(sys.argv[0]))
  parser.add_option(cli.DEBUG_OPT)
  parser.add_option(cli.VERBOSE_OPT)
  parser.add_option(cli.YES_DOIT_OPT)
  parser.add_option("--no-backup", dest="backup", default=True,
                    action="store_false",
                    help="Whether to create backup copies of deleted files")

  (opts, args) = parser.parse_args()

  return VerifyOptions(parser, opts, args)


def VerifyOptions(parser, opts, args):
  """Verifies options and arguments for correctness.

  """
  if args:
    parser.error("No arguments are expected")

  return opts


def Main():
  """Main routine.

  """
  opts = ParseOptions()

  utils.SetupToolLogging(opts.debug, opts.verbose)

  try:
    # List of files to delete. Contains tuples consisting of the absolute path
    # and a boolean denoting whether a backup copy should be created before
    # deleting.
    clean_files = [
      (pathutils.CONFD_HMAC_KEY, True),
      (pathutils.CLUSTER_CONF_FILE, True),
      (pathutils.CLUSTER_DOMAIN_SECRET_FILE, True),
      ]
    clean_files.extend((f, True) for f in pathutils.ALL_CERT_FILES)
    clean_files.extend((f, False) for f in ssconf.SimpleStore().GetFileList())

    if not opts.yes_do_it:
      cli.ToStderr("Cleaning a node is irreversible. If you really want to"
                   " clean this node, supply the --yes-do-it option.")
      return constants.EXIT_FAILURE

    logging.info("Stopping daemons")
    result = utils.RunCmd([pathutils.DAEMON_UTIL, "stop-all"],
                          interactive=True)
    if result.failed:
      raise Exception("Could not stop daemons, command '%s' failed: %s" %
                      (result.cmd, result.fail_reason))

    for (filename, backup) in clean_files:
      if os.path.exists(filename):
        if opts.backup and backup:
          logging.info("Backing up %s", filename)
          utils.CreateBackup(filename)

        logging.info("Removing %s", filename)
        utils.RemoveFile(filename)

    logging.info("Node successfully cleaned")
  except Exception as err: # pylint: disable=W0703
    logging.debug("Caught unhandled exception", exc_info=True)

    (retcode, message) = cli.FormatError(err)
    logging.error(message)

    return retcode
  else:
    return constants.EXIT_SUCCESS
