



"""Alcor python modules"""

try:
  from alcor import alcor # pylint: disable=W0406
except ImportError:
  pass
else:
  raise Exception("A module named \"alcor.alcor\" was successfully imported"
                  " and should be removed as it can lead to importing the"
                  " wrong module(s) in other parts of the code, consequently"
                  " leading to failures which are difficult to debug")
