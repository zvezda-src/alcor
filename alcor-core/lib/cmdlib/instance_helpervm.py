


"""Functions for running helper virtual machines to perform tasks on instances.

"""

import contextlib

from alcor import constants
from alcor import errors
from alcor.utils import retry

from alcor.cmdlib.common import IsInstanceRunning, DetermineImageSize
from alcor.cmdlib.instance_storage import StartInstanceDisks, \
  TemporaryDisk, ImageDisks


@contextlib.contextmanager
def HelperVM(lu, instance, vm_image, startup_timeout, vm_timeout,
             log_prefix=None, feedback_fn=None):
  """Runs a given helper VM for a given instance.

  @type lu: L{LogicalUnit}
  @param lu: the lu on whose behalf we execute
  @type instance: L{objects.Instance}
  @param instance: the instance definition
  @type vm_image: string
  @param vm_image: the name of the helper VM image to dump on a temporary disk
  @type startup_timeout: int
  @param startup_timeout: how long to wait for the helper VM to start up
  @type vm_timeout: int
  @param vm_timeout: how long to wait for the helper VM to finish its work
  @type log_prefix: string
  @param log_prefix: a prefix for all log messages
  @type feedback_fn: function
  @param feedback_fn: Function used to log progress

  """
  if log_prefix:
    add_prefix = lambda msg: "%s: %s" % (log_prefix, msg)
  else:
    add_prefix = lambda msg: msg

  if feedback_fn is not None:
    log_feedback = lambda msg: feedback_fn(add_prefix(msg))
  else:
    log_feedback = lambda _: None

  try:
    disk_size = DetermineImageSize(lu, vm_image, instance.primary_node)
  except errors.OpExecError as err:
    raise errors.OpExecError("Could not create temporary disk: %s", err)

  with TemporaryDisk(lu,
                     instance,
                     [(constants.DT_PLAIN, constants.DISK_RDWR, disk_size)],
                     log_feedback):
    log_feedback("Activating helper VM's temporary disks")
    StartInstanceDisks(lu, instance, False)

    log_feedback("Imaging temporary disks with image %s" % (vm_image, ))
    ImageDisks(lu, instance, vm_image)

    log_feedback("Starting helper VM")
    result = lu.rpc.call_instance_start(instance.primary_node,
                                        (instance, [], []),
                                        False, lu.op.reason)
    result.Raise(add_prefix("Could not start helper VM with image %s" %
                            (vm_image, )))

    # First wait for the instance to start up
    running_check = lambda: IsInstanceRunning(lu, instance, prereq=False)
    instance_up = retry.SimpleRetry(True, running_check, 5.0,
                                    startup_timeout)
    if not instance_up:
      raise errors.OpExecError(add_prefix("Could not boot instance using"
                                          " image %s" % (vm_image, )))

    log_feedback("Helper VM is up")

    def cleanup():
      log_feedback("Waiting for helper VM to finish")

      # Then for it to be finished, detected by its shutdown
      instance_up = retry.SimpleRetry(False, running_check, 20.0, vm_timeout)
      if instance_up:
        lu.LogWarning(add_prefix("Helper VM has not finished within the"
                                 " timeout; shutting it down forcibly"))
        return \
          lu.rpc.call_instance_shutdown(instance.primary_node,
                                        instance,
                                        constants.DEFAULT_SHUTDOWN_TIMEOUT,
                                        lu.op.reason)
      else:
        return None

    # Run the inner block and handle possible errors
    try:
      yield
    except Exception:
      # if the cleanup failed for some reason, log it and just re-raise
      result = cleanup()
      if result:
        result.Warn(add_prefix("Could not shut down helper VM with image"
                               " %s within timeout" % (vm_image, )))
        log_feedback("Error running helper VM with image %s" %
                     (vm_image, ))
      raise
    else:
      result = cleanup()
      # if the cleanup failed for some reason, throw an exception
      if result:
        result.Raise(add_prefix("Could not shut down helper VM with image %s"
                                " within timeout" % (vm_image, )))
        raise errors.OpExecError("Error running helper VM with image %s" %
                                 (vm_image, ))

  log_feedback("Helper VM execution completed")


def RunWithHelperVM(lu, instance, vm_image, startup_timeout, vm_timeout,
                    log_prefix=None, feedback_fn=None):
  """Runs a given helper VM for a given instance.

  @type lu: L{LogicalUnit}
  @param lu: the lu on whose behalf we execute
  @type instance: L{objects.Instance}
  @param instance: the instance definition
  @type vm_image: string
  @param vm_image: the name of the helper VM image to dump on a temporary disk
  @type startup_timeout: int
  @param startup_timeout: how long to wait for the helper VM to start up
  @type vm_timeout: int
  @param vm_timeout: how long to wait for the helper VM to finish its work
  @type log_prefix: string
  @param log_prefix: a prefix for all log messages
  @type feedback_fn: function
  @param feedback_fn: Function used to log progress


  """
  with HelperVM(lu, instance, vm_image, startup_timeout, vm_timeout,
                log_prefix=log_prefix, feedback_fn=feedback_fn):
    pass
