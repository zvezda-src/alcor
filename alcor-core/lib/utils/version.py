


"""Version utilities."""

import re

from alcor import constants

_FULL_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_SHORT_VERSION_RE = re.compile(r"(\d+)\.(\d+)")

FIRST_UPGRADE_VERSION = (2, 10, 0)

CURRENT_VERSION = (constants.VERSION_MAJOR, constants.VERSION_MINOR,
                   constants.VERSION_REVISION)




def BuildVersion(major, minor, revision):
  """Calculates int version number from major, minor and revision numbers.

  Returns: int representing version number

  """
  assert isinstance(major, int)
  assert isinstance(minor, int)
  assert isinstance(revision, int)
  return (1000000 * major +
            10000 * minor +
                1 * revision)


def SplitVersion(version):
  """Splits version number stored in an int.

  Returns: tuple; (major, minor, revision)

  """
  assert isinstance(version, int)

  (major, remainder) = divmod(version, 1000000)
  (minor, revision) = divmod(remainder, 10000)

  return (major, minor, revision)


def ParseVersion(versionstring):
  """Parses a version string.

  @param versionstring: the version string to parse
  @type versionstring: string
  @rtype: tuple or None
  @return: (major, minor, revision) if parsable, None otherwise.

  """
  m = _FULL_VERSION_RE.match(versionstring)
  if m is not None:
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

  m = _SHORT_VERSION_RE.match(versionstring)
  if m is not None:
    return (int(m.group(1)), int(m.group(2)), 0)

  return None


def UpgradeRange(target, current=CURRENT_VERSION):
  """Verify whether a version is within the range of automatic upgrades.

  @param target: The version to upgrade to as (major, minor, revision)
  @type target: tuple
  @param current: The version to upgrade from as (major, minor, revision)
  @type current: tuple
  @rtype: string or None
  @return: None, if within the range, and a human-readable error message
      otherwise

  """
  if target < FIRST_UPGRADE_VERSION or current < FIRST_UPGRADE_VERSION:
    return "automatic upgrades only supported from 2.10 onwards"

  if target[0] != current[0]:
    # allow major upgrade from 2.16 to 3.0
    if current[0:2] == (2,16) and target[0:2] == (3,0):
      return None
    # allow major downgrade from 3.0 to 2.16
    if current[0:2] == (3,0) and target[0:2] == (2,16):
      return None

    # forbid any other major version up-/downgrades
    return "major version up- or downgrades are only supported between " \
      "2.16 and 3.0"

  if target[1] < current[1] - 1:
    return "can only downgrade one minor version at a time"

  return None


def ShouldCfgdowngrade(version, current=CURRENT_VERSION):
  """Decide whether cfgupgrade --downgrade should be called.

  Given the current version and the version to change to, decide
  if in the transition process cfgupgrade --downgrade should
  be called

  @param version: The version to upgrade to as (major, minor, revision)
  @type version: tuple
  @param current: The version to upgrade from as (major, minor, revision)
  @type current: tuple
  @rtype: bool
  @return: True, if cfgupgrade --downgrade should be called.

  """
  return version[0] == current[0] and version[1] == current[1] - 1


def IsCorrectConfigVersion(targetversion, configversion):
  """Decide whether configuration version is compatible with the target.

  @param targetversion: The version to upgrade to as (major, minor, revision)
  @type targetversion: tuple
  @param configversion: The version of the current configuration
  @type configversion: tuple
  @rtype: bool
  @return: True, if the configversion fits with the target version.

  """
  return (configversion[0] == targetversion[0] and
          configversion[1] == targetversion[1])


def IsBefore(version, major, minor, revision):
  """Decide if a given version is strictly before a given version.

  @param version: (major, minor, revision) or None, with None being
      before all versions
  @type version: (int, int, int) or None
  @param major: major version
  @type major: int
  @param minor: minor version
  @type minor: int
  @param revision: revision
  @type revision: int

  """
  if version is None:
    return True

  return version < (major, minor, revision)


def IsEqual(version, major, minor, revision):
  """Decide if a given version matches the given version.

  If the revision is set to None, only major and minor are compared.

  @param version: (major, minor, revision) or None, with None being
      before all versions
  @type version: (int, int, int) or None
  @param major: major version
  @type major: int
  @param minor: minor version
  @type minor: int
  @param revision: revision
  @type revision: int

  """
  if version is None:
    return False

  if revision is None:
    current_major, current_minor, _ = version
    return (current_major, current_minor) == (major, minor)

  return version == (major, minor, revision)
