

"""Backup related commands"""


from alcor.cli import *
from alcor import opcodes
from alcor import constants
from alcor import errors
from alcor import qlang


_LIST_DEF_FIELDS = ["node", "export"]


def PrintExportList(opts, args):
  """Prints a list of all the exported system images.

  @param opts: the command line options selected by the user
  @type args: list
  @param args: should be an empty list
  @rtype: int
  @return: the desired exit code

  """
  selected_fields = ParseFields(opts.output, _LIST_DEF_FIELDS)

  qfilter = qlang.MakeSimpleFilter("node", opts.nodes)

  cl = GetClient()

  return GenericList(constants.QR_EXPORT, selected_fields, None, opts.units,
                     opts.separator, not opts.no_headers,
                     verbose=opts.verbose, qfilter=qfilter, cl=cl)


def ListExportFields(opts, args):
  """List export fields.

  @param opts: the command line options selected by the user
  @type args: list
  @param args: fields to list, or empty for all
  @rtype: int
  @return: the desired exit code

  """
  cl = GetClient()

  return GenericListFields(constants.QR_EXPORT, args, opts.separator,
                           not opts.no_headers, cl=cl)


def ExportInstance(opts, args):
  """Export an instance to an image in the cluster.

  @param opts: the command line options selected by the user
  @type args: list
  @param args: should contain only one element, the name
      of the instance to be exported
  @rtype: int
  @return: the desired exit code

  """
  ignore_remove_failures = opts.ignore_remove_failures

  if not opts.node:
    raise errors.OpPrereqError("Target node must be specified",
                               errors.ECODE_INVAL)

  op = opcodes.OpBackupExport(
    instance_name=args[0],
    target_node=opts.node,
    compress=opts.transport_compression,
    shutdown=opts.shutdown,
    shutdown_timeout=opts.shutdown_timeout,
    remove_instance=opts.remove_instance,
    ignore_remove_failures=ignore_remove_failures,
    zero_free_space=opts.zero_free_space,
    zeroing_timeout_fixed=opts.zeroing_timeout_fixed,
    zeroing_timeout_per_mib=opts.zeroing_timeout_per_mib,
    long_sleep=opts.long_sleep
  )

  SubmitOrSend(op, opts)
  return 0


def ImportInstance(opts, args):
  """Add an instance to the cluster.

  This is just a wrapper over GenericInstanceCreate.

  """
  return GenericInstanceCreate(constants.INSTANCE_IMPORT, opts, args)


def RemoveExport(opts, args):
  """Remove an export from the cluster.

  @param opts: the command line options selected by the user
  @type args: list
  @param args: should contain only one element, the name of the
      instance whose backup should be removed
  @rtype: int
  @return: the desired exit code

  """
  op = opcodes.OpBackupRemove(instance_name=args[0])

  SubmitOrSend(op, opts)
  return 0


import_opts = [
  IDENTIFY_DEFAULTS_OPT,
  SRC_DIR_OPT,
  SRC_NODE_OPT,
  COMPRESS_OPT,
  IGNORE_IPOLICY_OPT,
  HELPER_STARTUP_TIMEOUT_OPT,
  HELPER_SHUTDOWN_TIMEOUT_OPT,
  ]


commands = {
  "list": (
    PrintExportList, ARGS_NONE,
    [NODE_LIST_OPT, NOHDR_OPT, SEP_OPT, USEUNITS_OPT, FIELDS_OPT, VERBOSE_OPT],
    "", "Lists instance exports available in the alcor cluster"),
  "list-fields": (
    ListExportFields, [ArgUnknown()],
    [NOHDR_OPT, SEP_OPT],
    "[fields...]",
    "Lists all available fields for exports"),
  "export": (
    ExportInstance, ARGS_ONE_INSTANCE,
    [FORCE_OPT, SINGLE_NODE_OPT, TRANSPORT_COMPRESSION_OPT, NOSHUTDOWN_OPT,
     SHUTDOWN_TIMEOUT_OPT, REMOVE_INSTANCE_OPT, IGNORE_REMOVE_FAILURES_OPT,
     DRY_RUN_OPT, PRIORITY_OPT, ZERO_FREE_SPACE_OPT, ZEROING_TIMEOUT_FIXED_OPT,
     ZEROING_TIMEOUT_PER_MIB_OPT, LONG_SLEEP_OPT] + SUBMIT_OPTS,
    "-n <node-name> [opts...] <instance-name>",
    "Exports an instance to an image"),
  "import": (
    ImportInstance, ARGS_ONE_INSTANCE, COMMON_CREATE_OPTS + import_opts,
    "[...] -t disk-type -n node[:secondary-node] <instance-name>",
    "Imports an instance from an exported image"),
  "remove": (
    RemoveExport, [ArgUnknown(min=1, max=1)],
    [DRY_RUN_OPT, PRIORITY_OPT] + SUBMIT_OPTS,
    "<instance-name>", "Remove exports of named instance from the filesystem."),
  }


def Main():
  return GenericMain(commands)
