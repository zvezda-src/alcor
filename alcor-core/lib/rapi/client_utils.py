


"""RAPI client utilities.

"""

from alcor import constants
from alcor import cli

from alcor.rapi import client

HTTP_NOT_FOUND = 404


class RapiJobPollCb(cli.JobPollCbBase):
  def __init__(self, cl):
    """Initializes this class.

    @param cl: RAPI client instance

    """
    cli.JobPollCbBase.__init__(self)

    self.cl = cl

  def WaitForJobChangeOnce(self, job_id, fields,
                           prev_job_info, prev_log_serial,
                           timeout=constants.DEFAULT_WFJC_TIMEOUT):
    """Waits for changes on a job.

    """
    try:
      result = self.cl.WaitForJobChange(job_id, fields,
                                        prev_job_info, prev_log_serial)
    except client.AlcorApiError as err:
      if err.code == HTTP_NOT_FOUND:
        return None

      raise

    if result is None:
      return constants.JOB_NOTCHANGED

    return (result["job_info"], result["log_entries"])

  def QueryJobs(self, job_ids, fields):
    """Returns the given fields for the selected job IDs.

    @type job_ids: list of numbers
    @param job_ids: Job IDs
    @type fields: list of strings
    @param fields: Fields

    """
    if len(job_ids) != 1:
      raise NotImplementedError("Only one job supported at this time")

    try:
      result = self.cl.GetJobStatus(job_ids[0])
    except client.AlcorApiError as err:
      if err.code == HTTP_NOT_FOUND:
        return [None]

      raise

    return [[result[name] for name in fields], ]

  def CancelJob(self, job_id):
    """Cancels a currently running job.

    """
    return self.cl.CancelJob(job_id)


def PollJob(rapi_client, job_id, reporter):
  """Function to poll for the result of a job.

  @param rapi_client: RAPI client instance
  @type job_id: number
  @param job_id: Job ID
  @type reporter: L{cli.JobPollReportCbBase}
  @param reporter: PollJob reporter instance

  @return: The opresult of the job
  @raise errors.JobLost: If job can't be found
  @raise errors.OpExecError: if job didn't succeed

  @see: L{alcor.cli.GenericPollJob}

  """
  return cli.GenericPollJob(job_id, RapiJobPollCb(rapi_client), reporter)
