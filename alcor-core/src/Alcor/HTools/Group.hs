{-| Module describing a node group.

-}

{-
-}

module Alcor.HTools.Group
  ( Group(..)
  , List
  , AssocList
  -- * Constructor
  , create
  , setIdx
  , isAllocable
  , setUnallocable
  ) where

import qualified Alcor.HTools.Container as Container

import qualified Alcor.HTools.Types as T

-- * Type declarations

-- | The node group type.
data Group = Group
  { name        :: String        -- ^ The node name
  , uuid        :: T.GroupID     -- ^ The UUID of the group
  , idx         :: T.Gdx         -- ^ Internal index for book-keeping
  , allocPolicy :: T.AllocPolicy -- ^ The allocation policy for this group
  , networks    :: [T.NetworkID] -- ^ The networks connected to this group
  , iPolicy     :: T.IPolicy     -- ^ The instance policy for this group
  , allTags     :: [String]      -- ^ The tags for this group
  } deriving (Show, Eq)

-- Note: we use the name as the alias, and the UUID as the official
-- name
instance T.Element Group where
  nameOf     = uuid
  idxOf      = idx
  setAlias   = setName
  setIdx     = setIdx
  allNames n = [name n, uuid n]

-- | A simple name for the int, node association list.
type AssocList = [(T.Gdx, Group)]

-- | A simple name for a node map.
type List = Container.Container Group

-- * Initialization functions

-- | Create a new group.
create :: String        -- ^ The node name
       -> T.GroupID     -- ^ The UUID of the group
       -> T.AllocPolicy -- ^ The allocation policy for this group
       -> [T.NetworkID] -- ^ The networks connected to this group
       -> T.IPolicy     -- ^ The instance policy for this group
       -> [String]      -- ^ The tags for this group
       -> Group
create name_init id_init apol_init nets_init ipol_init tags_init =
  Group { name        = name_init
        , uuid        = id_init
        , allocPolicy = apol_init
        , networks    = nets_init
        , iPolicy     = ipol_init
        , allTags     = tags_init
        , idx         = -1
        }

-- | Sets the group index.
--
-- This is used only during the building of the data structures.
setIdx :: Group -> T.Gdx -> Group
setIdx t i = t {idx = i}

-- | Changes the alias.
--
-- This is used only during the building of the data structures.
setName :: Group -> String -> Group
setName t s = t { name = s }

-- | Checks if a group is allocable.
isAllocable :: Group -> Bool
isAllocable = (/= T.AllocUnallocable) . allocPolicy

-- | Makes the group unallocatable
setUnallocable :: Group -> Group
setUnallocable t = t { allocPolicy = T.AllocUnallocable }
