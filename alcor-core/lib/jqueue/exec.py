


"""Module implementing executing of a job as a separate process

The complete protocol of initializing a job is described in the haskell
module Alcor.Query.Exec
"""

import contextlib
import logging
import os
import signal
import sys
import time

from alcor import mcpu
from alcor.server import masterd
from alcor.rpc import transport
from alcor import serializer
from alcor import utils
from alcor import pathutils
from alcor.utils import livelock

from alcor.jqueue import _JobProcessor


def _SetupJob():
  """Setup the process to execute the job

  Retrieve the job id from argv, create a livelock and pass it to the master
  process and finally obtain any secret parameters.

  This also closes standard input/output.

  @rtype: (int, string, json encoding of a list of dicts)

  """
  job_id = int(sys.argv[1])
  ts = time.time()
  llock = livelock.LiveLock("job_%06d" % job_id)
  logging.debug("Opening transport over stdin/out")
  with contextlib.closing(transport.FdTransport((0, 1))) as trans:
    logging.debug("Sending livelock name to master")
    trans.Call(llock.GetPath()) # pylint: disable=E1101
    logging.debug("Reading secret parameters from the master process")
    secret_params = trans.Call("") # pylint: disable=E1101
    logging.debug("Got secret parameters.")
  return (job_id, llock, secret_params)


def RestorePrivateValueWrapping(json):
  """Wrap private values in JSON decoded structure.

  @param json: the json-decoded value to protect.

  """
  result = []

  for secrets_dict in json:
    if secrets_dict is None:
      data = serializer.PrivateDict()
    else:
      data = serializer.PrivateDict(secrets_dict)
    result.append(data)
  return result


def main():

  debug = int(os.environ["GNT_DEBUG"])

  logname = pathutils.GetLogFilename("jobs")
  utils.SetupLogging(logname, "job-startup", debug=debug)

  (job_id, llock, secret_params_serialized) = _SetupJob()

  secret_params = ""
  if secret_params_serialized:
    secret_params_json = serializer.LoadJson(secret_params_serialized)
    secret_params = RestorePrivateValueWrapping(secret_params_json)

  utils.SetupLogging(logname, "job-%s" % (job_id,), debug=debug)

  try:
    logging.debug("Preparing the context and the configuration")
    context = masterd.AlcorContext(llock)

    logging.debug("Registering signal handlers")

    cancel = [False]
    prio_change = [False]

    def _TermHandler(signum, _frame):
      logging.info("Killed by signal %d", signum)
      cancel[0] = True
    signal.signal(signal.SIGTERM, _TermHandler)

    def _HupHandler(signum, _frame):
      logging.debug("Received signal %d, old flag was %s, will set to True",
                    signum, mcpu.sighupReceived)
      mcpu.sighupReceived[0] = True
    signal.signal(signal.SIGHUP, _HupHandler)

    def _User1Handler(signum, _frame):
      logging.info("Received signal %d, indicating priority change", signum)
      prio_change[0] = True
    signal.signal(signal.SIGUSR1, _User1Handler)

    job = context.jobqueue.SafeLoadJobFromDisk(job_id, False)

    job.SetPid(os.getpid())

    if secret_params:
      for i in range(0, len(secret_params)):
        if hasattr(job.ops[i].input, "osparams_secret"):
          job.ops[i].input.osparams_secret = secret_params[i]

    execfun = mcpu.Processor(context, job_id, job_id).ExecOpCode
    proc = _JobProcessor(context.jobqueue, execfun, job)
    result = _JobProcessor.DEFER
    while result != _JobProcessor.FINISHED:
      result = proc()
      if result == _JobProcessor.WAITDEP and not cancel[0]:
        # Normally, the scheduler should avoid starting a job where the
        # dependencies are not yet finalised. So warn, but wait an continue.
        logging.warning("Got started despite a dependency not yet finished")
        time.sleep(5)
      if cancel[0]:
        logging.debug("Got cancel request, cancelling job %d", job_id)
        r = context.jobqueue.CancelJob(job_id)
        job = context.jobqueue.SafeLoadJobFromDisk(job_id, False)
        proc = _JobProcessor(context.jobqueue, execfun, job)
        logging.debug("CancelJob result for job %d: %s", job_id, r)
        cancel[0] = False
      if prio_change[0]:
        logging.debug("Received priority-change request")
        try:
          fname = os.path.join(pathutils.LUXID_MESSAGE_DIR, "%d.prio" % job_id)
          new_prio = int(utils.ReadFile(fname))
          utils.RemoveFile(fname)
          logging.debug("Changing priority of job %d to %d", job_id, new_prio)
          r = context.jobqueue.ChangeJobPriority(job_id, new_prio)
          job = context.jobqueue.SafeLoadJobFromDisk(job_id, False)
          proc = _JobProcessor(context.jobqueue, execfun, job)
          logging.debug("Result of changing priority of %d to %d: %s", job_id,
                        new_prio, r)
        except Exception: # pylint: disable=W0703
          logging.warning("Informed of priority change, but could not"
                          " read new priority")
        prio_change[0] = False

  except Exception: # pylint: disable=W0703
    logging.exception("Exception when trying to run job %d", job_id)
  finally:
    logging.debug("Job %d finalized", job_id)
    logging.debug("Removing livelock file %s", llock.GetPath())
    os.remove(llock.GetPath())

  sys.exit(0)

if __name__ == '__main__':
  main()
