{-# LANGUAGE MultiParamTypeClasses, TypeFamilies #-}

{-| Common types and functions for persistent resources

In particular:
- locks
- temporary reservations

-}

{-
-}

module Alcor.WConfd.Persistent
  ( Persistent(..)
  , writePersistentAsyncTask
  , readPersistent
  , persistentLocks
  , persistentTempRes
  ) where

import Control.Monad.Error
import System.Directory (doesFileExist)
import qualified Text.JSON as J

import Alcor.BasicTypes
import Alcor.Errors
import qualified Alcor.JSON as J
import Alcor.Locking.Waiting (emptyWaiting, releaseResources)
import Alcor.Locking.Locks (ClientId(..), AlcorLockWaiting)
import Alcor.Logging
import qualified Alcor.Path as Path
import Alcor.WConfd.Monad
import Alcor.WConfd.TempRes ( TempResState, emptyTempResState
                             , dropAllReservations)
import Alcor.Utils.Atomic
import Alcor.Utils.AsyncWorker

-- * Common definitions

-- ** The data type that collects all required operations

-- | A collection of operations needed for persisting a resource.
data Persistent a = Persistent
  { persName :: String
  , persPath :: IO FilePath
  , persEmpty :: a
  , persCleanup :: ClientId -> WConfdMonad ()
  -- ^ The clean-up action needs to be a full 'WConfdMonad' action as it
  -- might need to do some complex processing, such as notifying
  -- clients that some locks are available.
  }

-- ** Common functions

-- | Construct an asynchronous worker whose action is to save the
-- current state of the persistent state.
-- The worker's action reads the state using the given @IO@
-- action. Any inbetween changes to the file are tacitly ignored.
writePersistentAsyncTask
  :: (J.JSON a) => Persistent a -> IO a -> ResultG (AsyncWorker () ())
writePersistentAsyncTask pers readAction = mkAsyncWorker_ $
  catchError (do
    let prefix = "Async. " ++ persName pers ++ " writer: "
    fpath <- liftIO $ persPath pers
    logDebug $ prefix ++ "Starting write to " ++ fpath
    state <- liftIO readAction
    toErrorBase . liftIO . atomicWriteFile fpath . J.encode $ state
    logDebug $ prefix ++ "written"
  ) (logEmergency . (++) ("Can't write " ++ persName pers ++ " state: ")
                  . show)

-- | Load a persistent data structure from disk.
readPersistent :: (J.JSON a) => Persistent a -> ResultG a
readPersistent pers = do
  logDebug $ "Reading " ++ persName pers
  file <- liftIO $ persPath pers
  file_present <- liftIO $ doesFileExist file
  if file_present
    then
      liftIO (persPath pers >>= readFile)
        >>= J.fromJResultE ("parsing " ++ persName pers) . J.decodeStrict
    else do
      logInfo $ "Note: No saved data for " ++ persName pers
                ++ ", tacitly assuming empty."
      return (persEmpty pers)

-- * Implementations

-- ** Locks

persistentLocks :: Persistent AlcorLockWaiting
persistentLocks = Persistent
  { persName = "lock allocation state"
  , persPath = Path.lockStatusFile
  , persEmpty = emptyWaiting
  , persCleanup = modifyLockWaiting_ . releaseResources
  }

-- ** Temporary reservations

persistentTempRes :: Persistent TempResState
persistentTempRes = Persistent
  { persName = "temporary reservations"
  , persPath = Path.tempResStatusFile
  , persEmpty = emptyTempResState
  , persCleanup = modifyTempResState . const . dropAllReservations
  }
