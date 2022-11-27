{-| Main binary for all stand-alone data collectors

-}

{-
-}

module Main (main) where

import Alcor.Common
import Alcor.DataCollectors.CLI (genericOptions, defaultOptions)
import Alcor.DataCollectors.Program (personalities)

-- | Simple main function.
main :: IO ()
main = genericMainCmds defaultOptions personalities genericOptions
