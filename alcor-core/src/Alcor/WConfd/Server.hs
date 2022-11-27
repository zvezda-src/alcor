{-# LANGUAGE TemplateHaskell #-}

{-| The implementation of Alcor WConfd daemon server.

As TemplateHaskell require that splices be defined in a separate
module, we combine all the TemplateHaskell functionality that HTools
needs in this module (except the one for unittests).

-}

{-
-}

module Alcor.WConfd.Server where

import Control.Concurrent (forkIO)
import Control.Exception
import Control.Monad
import Control.Monad.Error

import Alcor.BasicTypes
import qualified Alcor.Constants as C
import Alcor.Daemon
import Alcor.Daemon.Utils (handleMasterVerificationOptions)
import Alcor.Logging (logDebug)
import qualified Alcor.Path as Path
import Alcor.THH.RPC
import Alcor.UDSServer
import Alcor.Errors (formatError)
import Alcor.Runtime
import Alcor.Utils
import Alcor.Utils.Livelock (mkLivelockFile)
import Alcor.WConfd.ConfigState
import Alcor.WConfd.ConfigVerify
import Alcor.WConfd.ConfigWriter
import Alcor.WConfd.Core
import Alcor.WConfd.DeathDetection (cleanupLocksTask)
import Alcor.WConfd.Monad
import Alcor.WConfd.Persistent

handler :: DaemonHandle -> RpcServer WConfdMonadInt
handler _ = $( mkRpcM exportedFunctions )


-- | Type alias for prepMain results
type PrepResult = (Server, DaemonHandle)

-- | Check function for luxid.
checkMain :: CheckFn ()
checkMain = handleMasterVerificationOptions

-- | Prepare function for luxid.
prepMain :: PrepFn () PrepResult
prepMain _ _ = do
  socket_path <- Path.defaultWConfdSocket
  cleanupSocket socket_path
  s <- describeError "binding to the socket" Nothing (Just socket_path)
         $ connectServer serverConfig True socket_path

  -- TODO: Lock the configuration file so that running the daemon twice fails?
  conf_file <- Path.clusterConfFile

  dh <- toErrorBase
        . withErrorT (strMsg . ("Initialization of the daemon failed" ++)
                             . formatError) $ do
    ents <- getEnts
    (cdata, cstat) <- loadConfigFromFile conf_file
    verifyConfigErr cdata
    lock <- readPersistent persistentLocks
    tempres <- readPersistent persistentTempRes
    (_, livelock) <- mkLivelockFile C.wconfLivelockPrefix
    mkDaemonHandle conf_file
                   (mkConfigState cdata)
                   lock
                   tempres
                   (saveConfigAsyncTask conf_file cstat)
                   (distMCsAsyncTask ents conf_file)
                   distSSConfAsyncTask
                   (writePersistentAsyncTask persistentLocks)
                   (writePersistentAsyncTask persistentTempRes)
                   livelock

  return (s, dh)

serverConfig :: ServerConfig
serverConfig = ServerConfig
                 -- All the daemons that need to talk to WConfd should be
                 -- running as the same user - the former master daemon user.
                 FilePermissions { fpOwner = Just AlcorWConfd
                                 , fpGroup = Just $ ExtraGroup DaemonsGroup
                                 , fpPermissions = 0o0600
                                 }
                 ConnectConfig { recvTmo = 60
                               , sendTmo = 60
                               }


-- | Main function.
main :: MainFn () PrepResult
main _ _ (server, dh) = do
  logDebug "Starting the cleanup task"
  _ <- forkIO $ runWConfdMonadInt cleanupLocksTask dh
  finally
    (forever $ runWConfdMonadInt (listener (handler dh) server) dh)
    (liftIO $ closeServer server)


-- | Options list and functions.
options :: [OptType]
options =
  [ oNoDaemonize
  , oNoUserChecks
  , oDebug
  , oSyslogUsage
  , oForceNode
  , oNoVoting
  , oYesDoIt
  ]
