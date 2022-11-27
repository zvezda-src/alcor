{-# LANGUAGE TemplateHaskell #-}

{-| Lenses for OpCodes

-}

{-
-}

module Alcor.OpCodes.Lens where

import Alcor.Lens (makeCustomLenses)
import Alcor.OpCodes

$(makeCustomLenses ''MetaOpCode)
$(makeCustomLenses ''CommonOpParams)

