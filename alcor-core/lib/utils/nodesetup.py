

"""Utility functions for manipulating /etc/hosts.

"""

from io import StringIO

from alcor import pathutils

from alcor.utils import algo
from alcor.utils import io


def SetEtcHostsEntry(file_name, ip, hostname, aliases):
  """Sets the name of an IP address and hostname in /etc/hosts.

  @type file_name: str
  @param file_name: path to the file to modify (usually C{/etc/hosts})
  @type ip: str
  @param ip: the IP address
  @type hostname: str
  @param hostname: the hostname to be added
  @type aliases: list
  @param aliases: the list of aliases to add for the hostname

  """
  # Ensure aliases are unique
  names = algo.UniqueSequence([hostname] + aliases)

  out = StringIO()

  def _write_entry(written):
    if not written:
      out.write("%s\t%s\n" % (ip, " ".join(names)))
    return True

  written = False
  for line in io.ReadFile(file_name).splitlines(True):
    fields = line.split()
    if fields and not fields[0].startswith("#") and ip == fields[0]:
      written = _write_entry(written)
    else:
      out.write(line)
  _write_entry(written)

  io.WriteFile(file_name, data=out.getvalue(), uid=0, gid=0, mode=0o644,
               keep_perms=io.KP_IF_EXISTS)


def AddHostToEtcHosts(hostname, ip):
  """Wrapper around SetEtcHostsEntry.

  @type hostname: str
  @param hostname: a hostname that will be resolved and added to
      L{pathutils.ETC_HOSTS}
  @type ip: str
  @param ip: The ip address of the host

  """
  SetEtcHostsEntry(pathutils.ETC_HOSTS, ip, hostname, [hostname.split(".")[0]])


def RemoveEtcHostsEntry(file_name, hostname):
  """Removes a hostname from /etc/hosts.

  IP addresses without names are removed from the file.

  @type file_name: str
  @param file_name: path to the file to modify (usually C{/etc/hosts})
  @type hostname: str
  @param hostname: the hostname to be removed

  """
  out = StringIO()

  for line in io.ReadFile(file_name).splitlines(True):
    fields = line.split()
    if len(fields) > 1 and not fields[0].startswith("#"):
      names = fields[1:]
      if hostname in names:
        while hostname in names:
          names.remove(hostname)
        if names:
          out.write("%s %s\n" % (fields[0], " ".join(names)))
        continue

    out.write(line)

  io.WriteFile(file_name, data=out.getvalue(), uid=0, gid=0, mode=0o644,
               keep_perms=io.KP_IF_EXISTS)


def RemoveHostFromEtcHosts(hostname):
  """Wrapper around RemoveEtcHostsEntry.

  @type hostname: str
  @param hostname: hostname that will be resolved and its
      full and shot name will be removed from
      L{pathutils.ETC_HOSTS}

  """
  RemoveEtcHostsEntry(pathutils.ETC_HOSTS, hostname)
  RemoveEtcHostsEntry(pathutils.ETC_HOSTS, hostname.split(".")[0])
