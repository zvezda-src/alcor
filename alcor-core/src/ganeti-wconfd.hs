{-| Alcor WConfD (config writer) daemon

-}

{-
-}

module Main (main) where

import qualified Alcor.WConfd.Server
import Alcor.Daemon
import Alcor.Runtime

-- | Main function.
main :: IO ()
main =
  genericMain AlcorWConfd
    Alcor.WConfd.Server.options
    Alcor.WConfd.Server.checkMain
    Alcor.WConfd.Server.prepMain
    Alcor.WConfd.Server.main
