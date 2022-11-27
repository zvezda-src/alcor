{-| Implementation of Alcor Lock field queries

The actual computation of the field values is done by forwarding
the request; so only have a minimal field definition here.

-}

{-
-}

module Alcor.Query.Locks
  ( fieldsMap
  , RuntimeData
  ) where

import qualified Text.JSON as J

import Control.Arrow (first)
import Data.Tuple (swap)

import Alcor.Locking.Allocation (OwnerState(..))
import Alcor.Locking.Locks (ClientId, ciIdentifier)
import Alcor.Query.Common
import Alcor.Query.Language
import Alcor.Query.Types

-- | The runtime information for locks. As all information about locks
-- is handled by WConfD, the actual information is obtained as live data.
-- The type represents the information for a single lock, even though all
-- locks are queried simultaneously, ahead of time.
type RuntimeData = ( [(ClientId, OwnerState)] -- current state
                   , [(ClientId, OwnerState)] -- pending requests
                   )

-- | Obtain the owners of a lock from the runtime data.
getOwners :: RuntimeData -> a -> ResultEntry
getOwners (ownerinfo, _) _ =
  rsNormal . map (J.encode . ciIdentifier . fst)
    $ ownerinfo

-- | Obtain the mode of a lock from the runtime data.
getMode :: RuntimeData -> a -> ResultEntry
getMode (ownerinfo, _) _
  | null ownerinfo = rsNormal J.JSNull
  | any ((==) OwnExclusive . snd) ownerinfo = rsNormal "exclusive"
  | otherwise = rsNormal "shared"

-- | Obtain the pending requests from the runtime data.
getPending :: RuntimeData -> a -> ResultEntry
getPending (_, pending) _ =
  rsNormal . map (swap . first ((:[]) . J.encode . ciIdentifier)) $ pending

-- | List of all lock fields.
lockFields :: FieldList String RuntimeData
lockFields =
  [ (FieldDefinition "name" "Name" QFTOther "Lock name",
     FieldSimple rsNormal, QffNormal)
  , (FieldDefinition "mode" "Mode" QFTOther "Mode in which the lock is\
                                             \ currently acquired\
                                             \ (exclusive or shared)",
     FieldRuntime getMode, QffNormal)
  , (FieldDefinition "owner" "Owner" QFTOther "Current lock owner(s)",
     FieldRuntime getOwners, QffNormal)
  , (FieldDefinition "pending" "Pending" QFTOther "Jobs waiting for the lock",
     FieldRuntime getPending, QffNormal)
  ]

-- | The lock fields map.
fieldsMap :: FieldMap String RuntimeData
fieldsMap = fieldListToFieldMap lockFields
