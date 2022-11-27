


"""Module for the WConfd protocol

"""

import logging
import random
import time

import alcor.rpc.client as cl
import alcor.rpc.stub.wconfd as stub
from alcor.rpc.transport import Transport
from alcor.rpc import errors


class Client(cl.AbstractStubClient, stub.ClientRpcStub):
  # R0904: Too many public methods
  # pylint: disable=R0904
  """High-level WConfD client implementation.

  This uses a backing Transport-like class on top of which it
  implements data serialization/deserialization.

  """
  def __init__(self, timeouts=None, transport=Transport, allow_non_master=None):
    """Constructor for the Client class.

    Arguments are the same as for L{AbstractClient}.

    """
    cl.AbstractStubClient.__init__(self,
                                   timeouts=timeouts,
                                   transport=transport,
                                   allow_non_master=allow_non_master)
    stub.ClientRpcStub.__init__(self)

    retries = 12
    for try_no in range(0, retries):
      try:
        self._InitTransport()
        return
      except errors.TimeoutError:
        logging.debug("Timout trying to connect to WConfD")
        if try_no == retries -1:
          raise
        logging.debug("Will retry")
        time.sleep(try_no * 10 + 10 * random.random())
