{-# LANGUAGE TemplateHaskell #-}
{-| Alcor monitoring agent daemon

-}

{-

Copyright (C) 2013 Google Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
