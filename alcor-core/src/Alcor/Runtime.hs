{-| Implementation of the runtime configuration details.

-}

{-

Copyright (C) 2011, 2012, 2013, 2014 Google Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-}

module Alcor.Runtime
  ( AlcorDaemon(..)
  , MiscGroup(..)
  , AlcorGroup(..)
  , RuntimeEnts(..)
  , daemonName
  , daemonOnlyOnMaster
  , daemonLogBase
  , daemonUser
  , daemonGroup
  , ExtraLogReason(..)
  , daemonLogFile
  , daemonsExtraLogbase
  , daemonsExtraLogFile
  , daemonPidFile
  , getEnts
  , verifyDaemonUser
  ) where

import Control.Monad
import Control.Monad.Error
import qualified Data.Map as M
import System.Exit
import System.FilePath
import System.IO
import System.Posix.Types
import System.Posix.User
import Text.Printf

import qualified Alcor.ConstantUtils as ConstantUtils
import qualified Alcor.Path as Path
import Alcor.BasicTypes

import AutoConf

data AlcorDaemon = AlcorMasterd
                  | AlcorMetad
                  | AlcorNoded
                  | AlcorRapi
                  | AlcorConfd
                  | AlcorWConfd
                  | AlcorKvmd
                  | AlcorLuxid
                  | AlcorMond
                    deriving (Show, Enum, Bounded, Eq, Ord)

data MiscGroup = DaemonsGroup
               | AdminGroup
                 deriving (Show, Enum, Bounded, Eq, Ord)

data AlcorGroup = DaemonGroup AlcorDaemon
                 | ExtraGroup MiscGroup
                   deriving (Show, Eq, Ord)

data RuntimeEnts = RuntimeEnts
  { reUserToUid :: M.Map AlcorDaemon UserID
  , reUidToUser :: M.Map UserID String
  , reGroupToGid :: M.Map AlcorGroup GroupID
  , reGidToGroup :: M.Map GroupID String
  }

-- | Returns the daemon name for a given daemon.
daemonName :: AlcorDaemon -> String
daemonName AlcorMasterd = "alcor-masterd"
daemonName AlcorMetad   = "alcor-metad"
daemonName AlcorNoded   = "alcor-noded"
daemonName AlcorRapi    = "alcor-rapi"
daemonName AlcorConfd   = "alcor-confd"
daemonName AlcorWConfd  = "alcor-wconfd"
daemonName AlcorKvmd    = "alcor-kvmd"
daemonName AlcorLuxid   = "alcor-luxid"
daemonName AlcorMond    = "alcor-mond"

-- | Returns whether the daemon only runs on the master node.
daemonOnlyOnMaster :: AlcorDaemon -> Bool
daemonOnlyOnMaster AlcorMasterd = True
daemonOnlyOnMaster AlcorMetad   = False
daemonOnlyOnMaster AlcorNoded   = False
daemonOnlyOnMaster AlcorRapi    = False
daemonOnlyOnMaster AlcorConfd   = False
daemonOnlyOnMaster AlcorWConfd  = True
daemonOnlyOnMaster AlcorKvmd    = False
daemonOnlyOnMaster AlcorLuxid   = True
daemonOnlyOnMaster AlcorMond    = False

-- | Returns the log file base for a daemon.
daemonLogBase :: AlcorDaemon -> String
daemonLogBase AlcorMasterd = "master-daemon"
daemonLogBase AlcorMetad   = "meta-daemon"
daemonLogBase AlcorNoded   = "node-daemon"
daemonLogBase AlcorRapi    = "rapi-daemon"
daemonLogBase AlcorConfd   = "conf-daemon"
daemonLogBase AlcorWConfd  = "wconf-daemon"
daemonLogBase AlcorKvmd    = "kvm-daemon"
daemonLogBase AlcorLuxid   = "luxi-daemon"
daemonLogBase AlcorMond    = "monitoring-daemon"

-- | Returns the configured user name for a daemon.
daemonUser :: AlcorDaemon -> String
daemonUser AlcorMasterd = AutoConf.masterdUser
daemonUser AlcorMetad   = AutoConf.metadUser
daemonUser AlcorNoded   = AutoConf.nodedUser
daemonUser AlcorRapi    = AutoConf.rapiUser
daemonUser AlcorConfd   = AutoConf.confdUser
daemonUser AlcorWConfd  = AutoConf.wconfdUser
daemonUser AlcorKvmd    = AutoConf.kvmdUser
daemonUser AlcorLuxid   = AutoConf.luxidUser
daemonUser AlcorMond    = AutoConf.mondUser

-- | Returns the configured group for a daemon.
daemonGroup :: AlcorGroup -> String
daemonGroup (DaemonGroup AlcorMasterd) = AutoConf.masterdGroup
daemonGroup (DaemonGroup AlcorMetad)   = AutoConf.metadGroup
daemonGroup (DaemonGroup AlcorNoded)   = AutoConf.nodedGroup
daemonGroup (DaemonGroup AlcorRapi)    = AutoConf.rapiGroup
daemonGroup (DaemonGroup AlcorConfd)   = AutoConf.confdGroup
daemonGroup (DaemonGroup AlcorWConfd)  = AutoConf.wconfdGroup
daemonGroup (DaemonGroup AlcorLuxid)   = AutoConf.luxidGroup
daemonGroup (DaemonGroup AlcorKvmd)    = AutoConf.kvmdGroup
daemonGroup (DaemonGroup AlcorMond)    = AutoConf.mondGroup
daemonGroup (ExtraGroup  DaemonsGroup)  = AutoConf.daemonsGroup
daemonGroup (ExtraGroup  AdminGroup)    = AutoConf.adminGroup

data ExtraLogReason = AccessLog | ErrorLog

-- | Some daemons might require more than one logfile.  Specifically,
-- right now only the Haskell http library "snap", used by the
-- monitoring daemon, requires multiple log files.
daemonsExtraLogbase :: AlcorDaemon -> ExtraLogReason -> String
daemonsExtraLogbase daemon AccessLog = daemonLogBase daemon ++ "-access"
daemonsExtraLogbase daemon ErrorLog = daemonLogBase daemon ++ "-error"

-- | Returns the log file for a daemon.
daemonLogFile :: AlcorDaemon -> IO FilePath
daemonLogFile daemon = do
  logDir <- Path.logDir
  return $ logDir </> daemonLogBase daemon <.> "log"

-- | Returns the extra log files for a daemon.
daemonsExtraLogFile :: AlcorDaemon -> ExtraLogReason -> IO FilePath
daemonsExtraLogFile daemon logreason = do
  logDir <- Path.logDir
  return $ logDir </> daemonsExtraLogbase daemon logreason <.> "log"

-- | Returns the pid file name for a daemon.
daemonPidFile :: AlcorDaemon -> IO FilePath
daemonPidFile daemon = do
  runDir <- Path.runDir
  return $ runDir </> daemonName daemon <.> "pid"

-- | All groups list. A bit hacking, as we can't enforce it's complete
-- at compile time.
allGroups :: [AlcorGroup]
allGroups = map DaemonGroup [minBound..maxBound] ++
            map ExtraGroup  [minBound..maxBound]

-- | Computes the group/user maps.
getEnts :: (Error e) => ResultT e IO RuntimeEnts
getEnts = do
  let userOf = liftM userID . liftIO . getUserEntryForName . daemonUser
  let groupOf = liftM groupID . liftIO . getGroupEntryForName . daemonGroup
  let allDaemons = [minBound..maxBound] :: [AlcorDaemon]
  users <- mapM userOf allDaemons
  groups <- mapM groupOf allGroups
  return $ RuntimeEnts
            (M.fromList $ zip allDaemons users)
            (M.fromList $ zip users (map daemonUser allDaemons))
            (M.fromList $ zip allGroups groups)
            (M.fromList $ zip groups (map daemonGroup allGroups))

-- | Checks whether a daemon runs as the right user.
verifyDaemonUser :: AlcorDaemon -> RuntimeEnts -> IO ()
verifyDaemonUser daemon ents = do
  myuid <- getEffectiveUserID
  -- note: we use directly ! as lookup failues shouldn't happen, due
  -- to the above map construction
  checkUidMatch (daemonName daemon) ((M.!) (reUserToUid ents) daemon) myuid

-- | Check that two UIDs are matching or otherwise exit.
checkUidMatch :: String -> UserID -> UserID -> IO ()
checkUidMatch name expected actual =
  when (expected /= actual) $ do
    hPrintf stderr "%s started using wrong user ID (%d), \
                   \expected %d\n" name
              (fromIntegral actual::Int)
              (fromIntegral expected::Int) :: IO ()
    exitWith $ ExitFailure ConstantUtils.exitFailure
