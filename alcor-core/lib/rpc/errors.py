


"""Module that defines a transport for RPC connections.

A transport can send to and receive messages from some endpoint.

"""

from alcor.errors import LuxiError


class ProtocolError(LuxiError):
  """Denotes an error in the LUXI protocol."""


class ConnectionClosedError(ProtocolError):
  """Connection closed error."""


class TimeoutError(ProtocolError):
  """Operation timeout error."""


class RequestError(ProtocolError):
  """Error on request.

  This signifies an error in the request format or request handling,
  but not (e.g.) an error in starting up an instance.

  Some common conditions that can trigger this exception:
    - job submission failed because the job data was wrong
    - query failed because required fields were missing

  """


class NoMasterError(ProtocolError):
  """The master cannot be reached.

  This means that the master daemon is not running or the socket has
  been removed.

  """


class PermissionError(ProtocolError):
  """Permission denied while connecting to the master socket.

  This means the user doesn't have the proper rights.

  """
