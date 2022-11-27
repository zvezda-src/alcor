{-# LANGUAGE TemplateHaskell #-}
{-| Alcor monitoring agent daemon

-}

{-
-}

module Main (main) where

import Data.List ((\\))

import Alcor.Daemon
import Alcor.DataCollectors (collectors)
import Alcor.DataCollectors.Types (dName)
import Alcor.Runtime
import qualified Alcor.Monitoring.Server as S
import qualified Alcor.Constants as C
import qualified Alcor.ConstantUtils as CU

-- Check constistency of defined data collectors and their names used for the
-- Python constant generation:
$(let names = map dName collectors
      missing = names \\ CU.toList C.dataCollectorNames
  in if null missing
    then return []
    else fail $ "Please add " ++ show missing
              ++ " to the Alcor.Constants.dataCollectorNames.")


-- | Options list and functions.
options :: [OptType]
options =
  [ oNoDaemonize
  , oNoUserChecks
  , oDebug
  , oBindAddress
  , oPort C.defaultMondPort
  ]

-- | Main function.
main :: IO ()
main =
  genericMain AlcorMond options
    S.checkMain
    S.prepMain
    S.main
