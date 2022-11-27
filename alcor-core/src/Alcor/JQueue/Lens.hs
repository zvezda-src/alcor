{-# LANGUAGE TemplateHaskell #-}

{-| Lenses for job-queue objects

-}

{-
-}

module Alcor.JQueue.Lens where

import Control.Lens.Prism (Prism', prism')

import Alcor.JQueue.Objects
import Alcor.Lens (makeCustomLenses)
import Alcor.OpCodes (MetaOpCode)

validOpCodeL :: Prism' InputOpCode MetaOpCode
validOpCodeL = prism' ValidOpCode $ \op ->
  case op of
    ValidOpCode mop -> Just mop
    _ -> Nothing

$(makeCustomLenses ''QueuedOpCode)

$(makeCustomLenses ''QueuedJob)

