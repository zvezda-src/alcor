{-# LANGUAGE TemplateHaskell, StandaloneDeriving #-}

{-| Objects in the job queue.

-}

{-
-}

module Alcor.JQueue.Objects
    ( Timestamp
    , InputOpCode(..)
    , QueuedOpCode(..)
    , QueuedJob(..)
    ) where

import Prelude hiding (id, log)
import qualified Text.JSON
import Text.JSON.Types

import Alcor.THH
import Alcor.THH.Field
import Alcor.Types
import Alcor.OpCodes

-- | The alcor queue timestamp type. It represents the time as the pair
-- of seconds since the epoch and microseconds since the beginning of the
-- second.
type Timestamp = (Int, Int)

-- | An input opcode.
data InputOpCode = ValidOpCode MetaOpCode -- ^ OpCode was parsed successfully
                 | InvalidOpCode JSValue  -- ^ Invalid opcode
                   deriving (Show, Eq, Ord)

-- | JSON instance for 'InputOpCode', trying to parse it and if
-- failing, keeping the original JSValue.
instance Text.JSON.JSON InputOpCode where
  showJSON (ValidOpCode mo) = Text.JSON.showJSON mo
  showJSON (InvalidOpCode inv) = inv
  readJSON v = case Text.JSON.readJSON v of
                 Text.JSON.Error _ -> return $ InvalidOpCode v
                 Text.JSON.Ok mo -> return $ ValidOpCode mo

$(buildObject "QueuedOpCode" "qo"
  [ simpleField "input"           [t| InputOpCode |]
  , simpleField "status"          [t| OpStatus    |]
  , simpleField "result"          [t| JSValue     |]
  , defaultField [| [] |] $
    simpleField "log"             [t| [(Int, Timestamp, ELogType, JSValue)] |]
  , simpleField "priority"        [t| Int         |]
  , optionalNullSerField $
    simpleField "start_timestamp" [t| Timestamp   |]
  , optionalNullSerField $
    simpleField "exec_timestamp"  [t| Timestamp   |]
  , optionalNullSerField $
    simpleField "end_timestamp"   [t| Timestamp   |]
  ])

deriving instance Ord QueuedOpCode

$(buildObject "QueuedJob" "qj"
  [ simpleField "id"                 [t| JobId          |]
  , simpleField "ops"                [t| [QueuedOpCode] |]
  , optionalNullSerField $
    simpleField "received_timestamp" [t| Timestamp      |]
  , optionalNullSerField $
    simpleField "start_timestamp"    [t| Timestamp      |]
  , optionalNullSerField $
    simpleField "end_timestamp"      [t| Timestamp      |]
  , optionalField $
    simpleField "livelock"           [t| FilePath      |]
  , optionalField $ processIdField "process_id"
  ])

deriving instance Ord QueuedJob
