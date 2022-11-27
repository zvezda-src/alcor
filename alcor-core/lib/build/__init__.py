

"""Module used during the Alcor build process"""

import imp
import os


def LoadModule(filename):
  """Loads an external module by filename.

  Use this function with caution. Python will always write the compiled source
  to a file named "${filename}c".

  @type filename: string
  @param filename: Path to module

  """
  (name, ext) = os.path.splitext(filename)

  fh = open(filename, "r")
  try:
    return imp.load_module(name, fh, filename, (ext, "r", imp.PY_SOURCE))
  finally:
    fh.close()
