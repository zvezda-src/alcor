{-| Function related to serialisation of WConfD requests

-}

{-
-}

module Alcor.WConfd.Language
  ( LockRequestType(..)
  , AlcorLockRequest
  , fromAlcorLockRequest
  ) where

import qualified Text.JSON as J

import Alcor.Locking.Allocation
import Alcor.Locking.Locks (AlcorLocks)

-- * Serialisation related to locking

-- | Operation to be carried out on a lock (request exclusive/shared ownership,
-- or release).
data LockRequestType = ReqExclusive | ReqShared | ReqRelease deriving (Eq, Show)

instance J.JSON LockRequestType where
  showJSON ReqExclusive = J.showJSON "exclusive"
  showJSON ReqShared = J.showJSON "shared"
  showJSON ReqRelease = J.showJSON "release"
  readJSON (J.JSString x) = let s = J.fromJSString x
                            in case s of
                              "exclusive" -> J.Ok ReqExclusive
                              "shared" -> J.Ok ReqShared
                              "release" -> J.Ok ReqRelease
                              _ -> J.Error $ "Unknown lock update request " ++ s
  readJSON _ = J.Error "Update requests need to be strings"

-- | The type describing how lock update requests are passed over the wire.
type AlcorLockRequest = [(AlcorLocks, LockRequestType)]

-- | Transform a Lock LockReqeustType pair into a LockRequest.
toLockRequest :: (AlcorLocks, LockRequestType) -> LockRequest AlcorLocks
toLockRequest (a, ReqExclusive) = requestExclusive a
toLockRequest (a, ReqShared) = requestShared a
toLockRequest (a, ReqRelease) = requestRelease a

-- | From a AlcorLockRequest obtain a list of
-- Alcor.Lock.Allocation.LockRequest, suitable to updateLocks.
fromAlcorLockRequest :: AlcorLockRequest -> [LockRequest AlcorLocks]
fromAlcorLockRequest = map toLockRequest
