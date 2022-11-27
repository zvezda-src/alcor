

"""Utility functions for tag related operations

"""

from alcor import constants


def GetExclusionPrefixes(ctags):
  """Extract the exclusion tag prefixes from the cluster tags

  """
  prefixes = set([])
  for tag in ctags:
    if tag.startswith(constants.EX_TAGS_PREFIX):
      prefixes.add(tag[len(constants.EX_TAGS_PREFIX):])
  return prefixes


def IsGoodTag(prefixes, tag):
  """Decide if a string is a tag

  @param prefixes: set of prefixes that would indicate
      the tag being suitable
  @param tag: the tag in question

  """
  for prefix in prefixes:
    if tag.startswith(prefix):
      return True
  return False
