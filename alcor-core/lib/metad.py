


"""Module for the Metad protocol

"""

import logging
import random
import time

from alcor import constants
from alcor import errors
import alcor.rpc.client as cl
from alcor.rpc.transport import Transport
from alcor.rpc.errors import TimeoutError


if constants.ENABLE_METAD:
  import alcor.rpc.stub.metad as stub

  class Client(cl.AbstractStubClient, stub.ClientRpcStub):
    """High-level Metad client implementation.

    This uses a backing Transport-like class on top of which it
    implements data serialization/deserialization.

    """
    def __init__(self, timeouts=None, transport=Transport):
      """Constructor for the Client class.

      Arguments are the same as for L{AbstractClient}.

      """
      cl.AbstractStubClient.__init__(self, timeouts, transport)
      stub.ClientRpcStub.__init__(self)

      retries = 12
      for try_no in range(0, retries):
        try:
          self._InitTransport()
          return
        except TimeoutError:
          logging.debug("Timout trying to connect to MetaD")
          if try_no == retries - 1:
            raise
          logging.debug("Will retry")
          time.sleep(try_no * 10 + 10 * random.random())

    def _InitTransport(self):
      """(Re)initialize the transport if needed.

      """
      if self.transport is None:
        self.transport = self.transport_class(self._GetAddress(),
                                              timeouts=self.timeouts,
                                              allow_non_master=True)

else:
  class Client(object):
    """An empty client representation that just throws an exception.

    """
    def __init__(self, _timeouts=None, _transport=None):
      raise errors.ProgrammerError("The metadata deamon is disabled, yet"
                                   " the client has been called")
