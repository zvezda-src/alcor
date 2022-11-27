{-| Metadata daemon server, which controls the configuration and web servers.

-}

{-
-}
module Alcor.Metad.Server (start) where

import Control.Concurrent
import qualified Data.Map (empty)

import Alcor.Daemon (DaemonOptions)
import Alcor.Metad.ConfigCore (MetadHandle(..))
import qualified Alcor.Metad.ConfigServer as ConfigServer
import qualified Alcor.Metad.WebServer as WebServer

start :: DaemonOptions -> IO ()
start opts =
  do config <- newMVar Data.Map.empty
     _ <- forkIO $ WebServer.start opts config
     ConfigServer.start opts (MetadHandle config)
