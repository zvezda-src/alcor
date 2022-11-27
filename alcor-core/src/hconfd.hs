{-| Alcor configuration query daemon

-}

{-
-}

module Main (main) where

import qualified Alcor.Confd.Server
import Alcor.Daemon
import Alcor.Runtime
import qualified Alcor.Constants as C

-- | Options list and functions.
options :: [OptType]
options =
  [ oNoDaemonize
  , oNoUserChecks
  , oDebug
  , oPort C.defaultConfdPort
  , oBindAddress
  , oSyslogUsage
  ]

-- | Main function.
main :: IO ()
main =
  genericMain AlcorConfd options
    Alcor.Confd.Server.checkMain
    Alcor.Confd.Server.prepMain
    Alcor.Confd.Server.main
