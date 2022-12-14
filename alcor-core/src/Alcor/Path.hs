{-| Path-related helper functions.

-}

{-
-}

module Alcor.Path
  ( dataDir
  , runDir
  , logDir
  , socketDir
  , luxidMessageDir
  , livelockDir
  , livelockFile
  , defaultQuerySocket
  , defaultWConfdSocket
  , defaultMetadSocket
  , confdHmacKey
  , clusterConfFile
  , lockStatusFile
  , tempResStatusFile
  , watcherPauseFile
  , nodedCertFile
  , nodedClientCertFile
  , queueDir
  , jobQueueSerialFile
  , jobQueueLockFile
  , jobQueueDrainFile
  , jobQueueArchiveSubDir
  , instanceReasonDir
  , getInstReasonFilename
  , jqueueExecutorPy
  ) where

import System.FilePath
import System.Posix.Env (getEnvDefault)

import AutoConf

-- | Simple helper to concat two paths.
pjoin :: IO String -> String -> IO String
pjoin a b = do
  a' <- a
  return $ a' </> b

-- | Returns the root directory, which can be either the real root or
-- the virtual root.
getRootDir :: IO FilePath
getRootDir = getEnvDefault "GANETI_ROOTDIR" ""

-- | Prefixes a path with the current root directory.
addNodePrefix :: FilePath -> IO FilePath
addNodePrefix path = do
  root <- getRootDir
  return $ root ++ path

-- | Directory for data.
dataDir :: IO FilePath
dataDir = addNodePrefix $ AutoConf.localstatedir </> "lib" </> "alcor"

-- | Helper for building on top of dataDir (internal).
dataDirP :: FilePath -> IO FilePath
dataDirP = (dataDir `pjoin`)

-- | Directory for runtime files.
runDir :: IO FilePath
runDir = addNodePrefix $ AutoConf.localstatedir </> "run" </> "alcor"

-- | Directory for log files.
logDir :: IO FilePath
logDir = addNodePrefix $ AutoConf.localstatedir </> "log" </> "alcor"

-- | Directory for Unix sockets.
socketDir :: IO FilePath
socketDir = runDir `pjoin` "socket"

-- | Directory for the jobs' livelocks.
livelockDir :: IO FilePath
livelockDir = runDir `pjoin` "livelocks"

-- | Directory for luxid to write messages to running jobs, like
-- requests to change the priority.
luxidMessageDir :: IO FilePath
luxidMessageDir = runDir `pjoin` "luxidmessages"

-- | A helper for building a job's livelock file. It prepends
-- 'livelockDir' to a given filename.
livelockFile :: FilePath -> IO FilePath
livelockFile = pjoin livelockDir

-- | The default LUXI socket for queries.
defaultQuerySocket :: IO FilePath
defaultQuerySocket = socketDir `pjoin` "alcor-query"

-- | The default WConfD socket for queries.
defaultWConfdSocket :: IO FilePath
defaultWConfdSocket = socketDir `pjoin` "alcor-wconfd"

-- | The default MetaD socket for communication.
defaultMetadSocket :: IO FilePath
defaultMetadSocket = socketDir `pjoin` "alcor-metad"

-- | Path to file containing confd's HMAC key.
confdHmacKey :: IO FilePath
confdHmacKey = dataDirP "hmac.key"

-- | Path to cluster configuration file.
clusterConfFile :: IO FilePath
clusterConfFile  = dataDirP "config.data"

-- | Path to the file representing the lock status.
lockStatusFile :: IO FilePath
lockStatusFile  = dataDirP "locks.data"

-- | Path to the file representing the lock status.
tempResStatusFile :: IO FilePath
tempResStatusFile  = dataDirP "tempres.data"

-- | Path to the watcher pause file.
watcherPauseFile :: IO FilePath
watcherPauseFile = dataDirP "watcher.pause"

-- | Path to the noded certificate.
nodedCertFile :: IO FilePath
nodedCertFile = dataDirP "server.pem"

-- | Path to the noded client certificate.
nodedClientCertFile :: IO FilePath
nodedClientCertFile = dataDirP "client.pem"

-- | Job queue directory.
queueDir :: IO FilePath
queueDir = dataDirP "queue"

-- | Job queue serial file.
jobQueueSerialFile :: IO FilePath
jobQueueSerialFile = queueDir `pjoin` "serial"

-- | Job queue lock file
jobQueueLockFile :: IO FilePath
jobQueueLockFile = queueDir `pjoin` "lock"

-- | Job queue drain file
jobQueueDrainFile :: IO FilePath
jobQueueDrainFile = queueDir `pjoin` "drain"

-- | Job queue archive directory.
jobQueueArchiveSubDir :: FilePath
jobQueueArchiveSubDir = "archive"

-- | Directory containing the reason trails for the last change of status of
-- instances.
instanceReasonDir :: IO FilePath
instanceReasonDir = runDir `pjoin` "instance-reason"

-- | The path of the file containing the reason trail for an instance, given the
-- instance name.
getInstReasonFilename :: String -> IO FilePath
getInstReasonFilename instName = instanceReasonDir `pjoin` instName

-- | The path to the Python executable for starting jobs.
jqueueExecutorPy :: IO FilePath
jqueueExecutorPy = return $ versionedsharedir
                            </> "alcor" </> "jqueue" </> "exec.py"
