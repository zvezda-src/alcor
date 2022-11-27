{-# LANGUAGE TupleSections, TemplateHaskell #-}
{-| Configuration server for the metadata daemon.

-}

{-
-}
module Alcor.Metad.ConfigServer where

import Control.Exception (finally)
import Control.Monad.Reader

import Alcor.Path as Path
import Alcor.Daemon (DaemonOptions, cleanupSocket, describeError)
import Alcor.Runtime (AlcorDaemon(..), AlcorGroup(..), MiscGroup(..))
import Alcor.THH.RPC
import Alcor.UDSServer (ConnectConfig(..), ServerConfig(..))
import qualified Alcor.UDSServer as UDSServer
import Alcor.Utils (FilePermissions(..))

import Alcor.Metad.ConfigCore

-- * The handler that converts RPCs to calls to the above functions

handler :: RpcServer MetadMonadInt
handler = $( mkRpcM exportedFunctions )

-- * The main server code

start :: DaemonOptions -> MetadHandle -> IO ()
start _ config = do
     socket_path <- Path.defaultMetadSocket
     cleanupSocket socket_path
     server <- describeError "binding to the socket" Nothing (Just socket_path)
               $ UDSServer.connectServer metadConfig True socket_path
     finally
       (forever $ runMetadMonadInt (UDSServer.listener handler server) config)
       (UDSServer.closeServer server)
  where
    metadConfig =
      ServerConfig
        -- The permission 0600 is completely acceptable because only the node
        -- daemon talks to the metadata daemon, and the node daemon runs as
        -- root.
        FilePermissions { fpOwner = Just AlcorMetad
                        , fpGroup = Just $ ExtraGroup DaemonsGroup
                        , fpPermissions = 0o0600
                        }
        ConnectConfig { recvTmo = 60
                      , sendTmo = 60
                      }
