{-| Module abstracting the node and instance container implementation.

This is currently implemented on top of an 'IntMap', which seems to
give the best performance for our workload.

-}

{-
-}

module Alcor.HTools.Container
  ( -- * Types
    Container
  , Key
  -- * Creation
  , IntMap.empty
  , IntMap.singleton
  , IntMap.fromList
  -- * Query
  , IntMap.size
  , IntMap.null
  , find
  , IntMap.findMax
  , IntMap.member
  , IntMap.lookup
  -- * Update
  , add
  , addTwo
  , IntMap.map
  , IntMap.mapAccum
  , IntMap.filter
  -- * Conversion
  , IntMap.elems
  , IntMap.keys
  -- * Element functions
  , nameOf
  , findByName
  ) where

import Control.Monad.Fail (MonadFail)
import qualified Data.IntMap as IntMap

import qualified Alcor.HTools.Types as T

-- | Our key type.

type Key = IntMap.Key

-- | Our container type.
type Container = IntMap.IntMap

-- | Locate a key in the map (must exist).
find :: Key -> Container a -> a
find k = (IntMap.! k)

-- | Add or update one element to the map.
add :: Key -> a -> Container a -> Container a
add = IntMap.insert

-- | Add or update two elements of the map.
addTwo :: Key -> a -> Key -> a -> Container a -> Container a
addTwo k1 v1 k2 v2 = add k1 v1 . add k2 v2

-- | Compute the name of an element in a container.
nameOf :: (T.Element a) => Container a -> Key -> String
nameOf c k = T.nameOf $ find k c

-- | Find an element by name in a Container; this is a very slow function.
findByName :: (T.Element a, MonadFail m) =>
              Container a -> String -> m a
findByName c n =
  let all_elems = IntMap.elems c
      result = filter ((n `elem`) . T.allNames) all_elems
  in case result of
       [item] -> return item
       _ -> fail $ "Wrong number of elems found with name " ++ n
