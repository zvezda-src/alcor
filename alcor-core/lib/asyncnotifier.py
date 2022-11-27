


"""Asynchronous pyinotify implementation"""


import asyncore
import logging

try:
  from pyinotify import pyinotify
except ImportError:
  import pyinotify

from alcor import daemon
from alcor import errors


class AsyncNotifier(asyncore.file_dispatcher):
  """An asyncore dispatcher for inotify events.

  """
  def __init__(self, watch_manager, default_proc_fun=None, map=None):
    """Initializes this class.

    This is a a special asyncore file_dispatcher that actually wraps a
    pyinotify Notifier, making it asyncronous.

    """
    if default_proc_fun is None:
      default_proc_fun = pyinotify.ProcessEvent()

    self.notifier = pyinotify.Notifier(watch_manager, default_proc_fun)

    self.fd = self.notifier._fd
    asyncore.file_dispatcher.__init__(self, self.fd, map)

  def handle_read(self):
    self.notifier.read_events()
    self.notifier.process_events()


class ErrorLoggingAsyncNotifier(AsyncNotifier,
                                daemon.AlcorBaseAsyncoreDispatcher):
  """An asyncnotifier that can survive errors in the callbacks.

  We define this as a separate class, since we don't want to make AsyncNotifier
  diverge from what we contributed upstream.

  """


class FileEventHandlerBase(pyinotify.ProcessEvent):
  """Base class for file event handlers.

  @ivar watch_manager: Inotify watch manager

  """
  def __init__(self, watch_manager):
    """Initializes this class.

    @type watch_manager: pyinotify.WatchManager
    @param watch_manager: inotify watch manager

    """
    self.watch_manager = watch_manager

  def process_default(self, event):
    logging.error("Received unhandled inotify event: %s", event)

  def AddWatch(self, filename, mask):
    """Adds a file watch.

    @param filename: Path to file
    @param mask: Inotify event mask
    @return: Result

    """
    result = self.watch_manager.add_watch(filename, mask)

    ret = result.get(filename, -1)
    if ret <= 0:
      raise errors.InotifyError("Could not add inotify watcher (error code %s);"
                                " increasing fs.inotify.max_user_watches sysctl"
                                " might be necessary" % ret)

    return result[filename]

  def RemoveWatch(self, handle):
    """Removes a handle from the watcher.

    @param handle: Inotify handle
    @return: Whether removal was successful

    """
    result = self.watch_manager.rm_watch(handle)

    return result[handle]


class SingleFileEventHandler(FileEventHandlerBase):
  """Handle modify events for a single file.

  """
  def __init__(self, watch_manager, callback, filename):
    """Constructor for SingleFileEventHandler

    @type watch_manager: pyinotify.WatchManager
    @param watch_manager: inotify watch manager
    @type callback: function accepting a boolean
    @param callback: function to call when an inotify event happens
    @type filename: string
    @param filename: config file to watch

    """
    FileEventHandlerBase.__init__(self, watch_manager)

    self._callback = callback
    self._filename = filename

    self._watch_handle = None

  def enable(self):
    """Watch the given file.

    """
    if self._watch_handle is not None:
      return

    mask = (pyinotify.EventsCodes.ALL_FLAGS["IN_MODIFY"] |
            pyinotify.EventsCodes.ALL_FLAGS["IN_IGNORED"])

    self._watch_handle = self.AddWatch(self._filename, mask)

  def disable(self):
    """Stop watching the given file.

    """
    if self._watch_handle is not None and self.RemoveWatch(self._watch_handle):
      self._watch_handle = None

  def process_IN_IGNORED(self, event):
    logging.debug("Received 'ignored' inotify event for %s", event.path)
    self._watch_handle = None
    self._callback(False)

  def process_IN_MODIFY(self, event):
    logging.debug("Received 'modify' inotify event for %s", event.path)
    self._callback(True)
