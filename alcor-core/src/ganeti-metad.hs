{-| Metadata daemon.

-}

{-
-}

module Main (main) where

import qualified Alcor.Constants as Constants
import Alcor.Daemon (OptType)
import qualified Alcor.Daemon as Daemon
import qualified Alcor.Metad.Server as Server
import qualified Alcor.Runtime as Runtime

options :: [OptType]
options =
  [ Daemon.oBindAddress
  , Daemon.oDebug
  , Daemon.oNoDaemonize
  , Daemon.oNoUserChecks
  , Daemon.oPort Constants.defaultMetadPort
  ]

main :: IO ()
main =
  Daemon.genericMain Runtime.AlcorMetad options
    (\_ -> return . Right $ ())
    (\_ _ -> return ())
    (\opts _ _ -> Server.start opts)
