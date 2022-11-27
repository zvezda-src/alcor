

"""External Storage related commands"""


from alcor.cli import *
from alcor import opcodes
from alcor import utils


def ShowExtStorageInfo(opts, args):
  """List detailed information about ExtStorage providers.

  @param opts: the command line options selected by the user
  @type args: list
  @param args: empty list or list of ExtStorage providers' names
  @rtype: int
  @return: the desired exit code

  """
  op = opcodes.OpExtStorageDiagnose(output_fields=["name", "nodegroup_status",
                                                   "parameters"],
                                    names=[])

  result = SubmitOpCode(op, opts=opts)

  if not result:
    ToStderr("Can't get the ExtStorage providers list")
    return 1

  do_filter = bool(args)

  for (name, nodegroup_data, parameters) in result:
    if do_filter:
      if name not in args:
        continue
      else:
        args.remove(name)

    nodegroups_valid = []
    for nodegroup_name, nodegroup_status in nodegroup_data.items():
      if nodegroup_status:
        nodegroups_valid.append(nodegroup_name)

    ToStdout("%s:", name)

    if nodegroups_valid != []:
      ToStdout("  - Valid for nodegroups:")
      for ndgrp in utils.NiceSort(nodegroups_valid):
        ToStdout("      %s", ndgrp)
      ToStdout("  - Supported parameters:")
      for pname, pdesc in parameters:
        ToStdout("      %s: %s", pname, pdesc)
    else:
      ToStdout("  - Invalid for all nodegroups")

    ToStdout("")

  if args:
    for name in args:
      ToStdout("%s: Not Found", name)
      ToStdout("")

  return 0


def _ExtStorageStatus(status, diagnose):
  """Beautifier function for ExtStorage status.

  @type status: boolean
  @param status: is the ExtStorage provider valid
  @type diagnose: string
  @param diagnose: the error message for invalid ExtStorages
  @rtype: string
  @return: a formatted status

  """
  if status:
    return "valid"
  else:
    return "invalid - %s" % diagnose


def DiagnoseExtStorage(opts, args):
  """Analyse all ExtStorage providers.

  @param opts: the command line options selected by the user
  @type args: list
  @param args: should be an empty list
  @rtype: int
  @return: the desired exit code

  """
  op = opcodes.OpExtStorageDiagnose(output_fields=["name", "node_status",
                                                   "nodegroup_status"],
                                    names=[])

  result = SubmitOpCode(op, opts=opts)

  if not result:
    ToStderr("Can't get the list of ExtStorage providers")
    return 1

  for provider_name, node_data, nodegroup_data in result:

    nodes_valid = {}
    nodes_bad = {}
    nodegroups_valid = {}
    nodegroups_bad = {}

    # Per node diagnose
    for node_name, node_info in node_data.items():
      if node_info: # at least one entry in the per-node list
        (fo_path, fo_status, fo_msg, fo_params) = node_info.pop(0)
        fo_msg = "%s (path: %s)" % (_ExtStorageStatus(fo_status, fo_msg),
                                    fo_path)
        if fo_params:
          fo_msg += (" [parameters: %s]" %
                     utils.CommaJoin([v[0] for v in fo_params]))
        else:
          fo_msg += " [no parameters]"
        if fo_status:
          nodes_valid[node_name] = fo_msg
        else:
          nodes_bad[node_name] = fo_msg
      else:
        nodes_bad[node_name] = "ExtStorage provider not found"

    # Per nodegroup diagnose
    for nodegroup_name, nodegroup_status in nodegroup_data.items():
      status = nodegroup_status
      if status:
        nodegroups_valid[nodegroup_name] = "valid"
      else:
        nodegroups_bad[nodegroup_name] = "invalid"

    def _OutputPerNodegroupStatus(msg_map):
      map_k = utils.NiceSort(msg_map)
      for nodegroup in map_k:
        ToStdout("  For nodegroup: %s --> %s", nodegroup,
                 msg_map[nodegroup])

    def _OutputPerNodeStatus(msg_map):
      map_k = utils.NiceSort(msg_map)
      for node_name in map_k:
        ToStdout("  Node: %s, status: %s", node_name, msg_map[node_name])

    # Print the output
    st_msg = "Provider: %s" % provider_name
    ToStdout(st_msg)
    ToStdout("---")
    _OutputPerNodeStatus(nodes_valid)
    _OutputPerNodeStatus(nodes_bad)
    ToStdout("  --")
    _OutputPerNodegroupStatus(nodegroups_valid)
    _OutputPerNodegroupStatus(nodegroups_bad)
    ToStdout("")

  return 0


commands = {
  "diagnose": (
    DiagnoseExtStorage, ARGS_NONE, [PRIORITY_OPT],
    "", "Diagnose all ExtStorage providers"),
  "info": (
    ShowExtStorageInfo, [ArgOs()], [PRIORITY_OPT],
    "", "Show info about ExtStorage providers"),
  }


def Main():
  return GenericMain(commands)
