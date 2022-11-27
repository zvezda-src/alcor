{-| Implementation of the Alcor Query2 basic types.

These are types internal to the library, and for example clients that
use the library should not need to import it.

 -}

{-
-}

module Alcor.Query.Types
  ( FieldGetter(..)
  , QffMode(..)
  , FieldData
  , FieldList
  , FieldMap
  , isRuntimeField
  , fieldListToFieldMap
  ) where

import qualified Data.Map as Map

import Alcor.Query.Language
import Alcor.Objects

-- | The type of field getters. The \"a\" type represents the type
-- we're querying, whereas the \"b\" type represents the \'runtime\'
-- data for that type (if any). Note that we don't support multiple
-- runtime sources, and we always consider the entire configuration as
-- a given (so no equivalent for Python's /*_CONFIG/ and /*_GROUP/;
-- configuration accesses are cheap for us).
data FieldGetter a b = FieldSimple        (a -> ResultEntry)
                     | FieldRuntime       (b -> a -> ResultEntry)
                     | FieldConfig        (ConfigData -> a -> ResultEntry)
                     | FieldConfigRuntime (ConfigData -> b -> a -> ResultEntry)
                     | FieldUnknown

-- | Type defining how the value of a field is used in filtering. This
-- implements the equivalent to Python's QFF_ flags, except that we
-- don't use OR-able values.
data QffMode = QffNormal     -- ^ Value is used as-is in filters
             | QffTimestamp  -- ^ Value is a timestamp tuple, convert to float
             | QffHostname   -- ^ Value is a hostname, compare it smartly
               deriving (Show, Eq)


-- | Alias for a field data (definition and getter).
type FieldData a b = (FieldDefinition, FieldGetter a b, QffMode)

-- | Alias for a field data list.
type FieldList a b = [FieldData a b]

-- | Alias for field maps.
type FieldMap a b = Map.Map String (FieldData a b)

-- | Helper function to check if a getter is a runtime one.
isRuntimeField :: FieldGetter a b -> Bool
isRuntimeField FieldRuntime {}       = True
isRuntimeField FieldConfigRuntime {} = True
isRuntimeField _                     = False

-- | Helper function to obtain a FieldMap from the corresponding FieldList.
fieldListToFieldMap :: FieldList a b -> FieldMap a b
fieldListToFieldMap = Map.fromList . map (\v@(f, _, _) -> (fdefName f, v))
