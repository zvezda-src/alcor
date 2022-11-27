{-| Utility function for detecting the death of a job holding resources

To clean up resources owned by jobs that die for some reason, we need
to detect whether a job is still alive. As we have no control over PID
reuse, our approach is that each requester for a resource has to provide
a file where it owns an exclusive lock on. The kernel will make sure the
lock is removed if the process dies. We can probe for such a lock by
requesting a shared lock on the file.

-}

{-
-}

module Alcor.WConfd.DeathDetection
  ( cleanupLocksTask
  , cleanupLocks
  ) where

import Control.Concurrent (threadDelay)
import qualified Control.Exception as E
import Control.Monad
import System.Directory (removeFile)

import Alcor.BasicTypes
import qualified Alcor.Constants as C
import qualified Alcor.Locking.Allocation as L
import Alcor.Locking.Locks (ClientId(..))
import Alcor.Logging.Lifted (logDebug, logInfo)
import Alcor.Utils.Livelock
import Alcor.WConfd.Monad
import Alcor.WConfd.Persistent

-- | Interval to run clean-up tasks in microseconds
cleanupInterval :: Int
cleanupInterval = C.wconfdDeathdetectionIntervall * 1000000

-- | Go through all owners once and clean them up, if they're dead.
cleanupLocks :: WConfdMonad ()
cleanupLocks = do
  owners <- liftM L.lockOwners readLockAllocation
  mylivelock <- liftM dhLivelock daemonHandle
  logDebug $ "Current lock owners: " ++ show owners
  let cleanupIfDead owner = do
        let fpath = ciLockFile owner
        died <- if fpath == mylivelock
                  then return False
                  else liftIO (isDead fpath)
        when died $ do
          logInfo $ show owner ++ " died, releasing locks and reservations"
          persCleanup persistentTempRes owner
          persCleanup persistentLocks owner
          _ <- liftIO . E.try $ removeFile fpath
               :: WConfdMonad (Either IOError ())
          return ()
  mapM_ cleanupIfDead owners

-- | Thread periodically cleaning up locks of lock owners that died.
cleanupLocksTask :: WConfdMonadInt ()
cleanupLocksTask = forever . runResultT $ do
  logDebug "Death detection timer fired"
  cleanupLocks
  remainingFiles <- liftIO listLiveLocks
  mylivelock <- liftM dhLivelock daemonHandle
  logDebug $ "Livelockfiles remaining: " ++ show remainingFiles
  let cleanupStaleIfDead fpath = do
        died <- if fpath == mylivelock
                  then return False
                  else liftIO (isDead fpath)
        when died $ do
          logInfo $ "Cleaning up stale file " ++ fpath
          _ <- liftIO . E.try $ removeFile fpath
               :: WConfdMonad (Either IOError ())
          return ()
  mapM_ cleanupStaleIfDead remainingFiles
  liftIO $ threadDelay cleanupInterval
