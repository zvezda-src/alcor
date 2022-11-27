{-# LANGUAGE TemplateHaskell #-}

{-| The Alcor WConfd client functions.

The client functions are automatically generated from Alcor.WConfd.Core

-}

{-
-}

module Alcor.WConfd.Client where

import Control.Exception.Lifted (bracket)

import Alcor.THH.HsRPC
import Alcor.Constants
import Alcor.JSON (unMaybeForJSON)
import Alcor.Locking.Locks (ClientId)
import Alcor.Objects (ConfigData)
import Alcor.UDSServer (ConnectConfig(..), Client, connectClient)
import Alcor.WConfd.Core (exportedFunctions)

-- * Generated client functions

$(mkRpcCalls exportedFunctions)

-- * Helper functions for creating the client

-- | The default WConfd client configuration
wconfdConnectConfig :: ConnectConfig
wconfdConnectConfig = ConnectConfig { recvTmo    = wconfdDefRwto
                                    , sendTmo    = wconfdDefRwto
                                    }

-- | Given a socket path, creates a WConfd client with the default
-- configuration and timeout.
getWConfdClient :: FilePath -> IO Client
getWConfdClient = connectClient wconfdConnectConfig wconfdDefCtmo

-- * Helper functions for getting a remote lock

-- | Calls the `lockConfig` RPC until the lock is obtained.
waitLockConfig :: ClientId
               -> Bool  -- ^ whether the lock shall be in shared mode
               -> RpcClientMonad ConfigData
waitLockConfig c shared = do
  mConfigData <- lockConfig c shared
  case unMaybeForJSON mConfigData of
    Just configData -> return configData
    Nothing         -> waitLockConfig c shared

-- | Calls the `lockConfig` RPC until the lock is obtained,
-- runs a function on the obtained config, and calls `unlockConfig`.
withLockedConfig :: ClientId
                 -> Bool  -- ^ whether the lock shall be in shared mode
                 -> (ConfigData -> RpcClientMonad a)  -- ^ action to run
                 -> RpcClientMonad a
withLockedConfig c shared =
  -- Unlock config even if something throws.
  bracket (waitLockConfig c shared) (const $ unlockConfig c)
