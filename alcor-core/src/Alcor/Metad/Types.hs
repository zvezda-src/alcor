{-| Metadata daemon types.

-}

{-
-}
module Alcor.Metad.Types where

import Data.Map (Map)
import Text.JSON

type InstanceParams = Map String JSValue
