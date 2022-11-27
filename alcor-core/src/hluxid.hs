{-| Alcor query daemon

-}

{-
-}

module Main (main) where

import qualified Alcor.Query.Server
import Alcor.Daemon
import Alcor.Runtime

-- | Options list and functions.
options :: [OptType]
options =
  [ oNoDaemonize
  , oNoUserChecks
  , oDebug
  , oSyslogUsage
  , oNoVoting
  , oYesDoIt
  ]

-- | Main function.
main :: IO ()
main =
  genericMain AlcorLuxid options
    Alcor.Query.Server.checkMain
    Alcor.Query.Server.prepMain
    Alcor.Query.Server.main
