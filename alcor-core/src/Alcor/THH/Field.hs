{-# LANGUAGE TemplateHaskell #-}

{-| Helpers for creating various kinds of 'Field's.

They aren't directly needed for the Template Haskell code in Alcor.THH,
so better keep them in a separate module.

-}

{-
-}

module Alcor.THH.Field
  ( specialNumericalField
  , timeAsDoubleField
  , timeStampFields
  , uuidFields
  , serialFields
  , TagSet(..)
  , emptyTagSet
  , tagsFields
  , fileModeAsIntField
  , processIdField
  ) where

import Control.Applicative ((<$>))
import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.Set as Set
import Language.Haskell.TH
import qualified Text.JSON as JSON
import System.Posix.Types (FileMode, ProcessID)
import System.Time (ClockTime(..))

import Alcor.JSON (TimeAsDoubleJSON(..))
import Alcor.THH

-- * Internal functions

-- | Wrapper around a special parse function, suitable as field-parsing
-- function.
numericalReadFn :: JSON.JSON a => (String -> JSON.Result a)
                   -> [(String, JSON.JSValue)] -> JSON.JSValue -> JSON.Result a
numericalReadFn _ _ v@(JSON.JSRational _ _) = JSON.readJSON v
numericalReadFn f _ (JSON.JSString x) = f $ JSON.fromJSString x
numericalReadFn _ _ _ = JSON.Error "A numerical field has to be a number or\
                                   \ a string."

-- | Sets the read function to also accept string parsable by the given
-- function.
specialNumericalField :: Name -> Field -> Field
specialNumericalField f field =
     field { fieldRead = Just (appE (varE 'numericalReadFn) (varE f)) }

-- | Creates a new mandatory field that reads time as the (floating point)
-- number of seconds since the standard UNIX epoch, and represents it in
-- Haskell as 'ClockTime'.
timeAsDoubleField :: String -> Field
timeAsDoubleField fname =
  (simpleField fname [t| ClockTime |])
    { fieldRead = Just $ [| \_ -> liftM unTimeAsDoubleJSON . JSON.readJSON |]
    , fieldShow = Just $ [| \c -> (JSON.showJSON $ TimeAsDoubleJSON c, []) |]
    }

-- | A helper function for creating fields whose Haskell representation is
-- 'Integral' and which are serialized as numbers.
integralField :: Q Type -> String -> Field
integralField typq fname =
  let (~->) = appT . appT arrowT  -- constructs an arrow type
      (~::) = sigE . varE         -- (f ~:: t) constructs (f :: t)
  in (simpleField fname typq)
      { fieldRead = Just $
        [| \_ -> liftM $('fromInteger ~:: (conT ''Integer ~-> typq))
                   . JSON.readJSON |]
      , fieldShow = Just $
          [| \c -> (JSON.showJSON
                    . $('toInteger ~:: (typq ~-> conT ''Integer))
                    $ c, []) |]
      }

-- * External functions and data types

-- | Timestamp fields description.
timeStampFields :: [Field]
timeStampFields = map (defaultField [| TOD 0 0 |] . timeAsDoubleField)
                      ["ctime", "mtime"]


-- | Serial number fields description.
serialFields :: [Field]
serialFields =
    [ presentInForthcoming . renameField  "Serial"
        $ simpleField "serial_no" [t| Int |] ]

-- | UUID fields description.
uuidFields :: [Field]
uuidFields = [ presentInForthcoming $ simpleField "uuid" [t| BS.ByteString |] ]

-- | Tag set type.
newtype TagSet = TagSet { unTagSet :: Set.Set String }
  deriving (Eq, Show)

instance JSON.JSON TagSet where
  showJSON = JSON.showJSON . unTagSet
  readJSON = (TagSet <$>) . JSON.readJSON

-- | Empty tag set value.
emptyTagSet :: TagSet
emptyTagSet = TagSet Set.empty

-- | Tag field description.
tagsFields :: [Field]
tagsFields = [ defaultField [| emptyTagSet |] $
               simpleField "tags" [t| TagSet |] ]

-- ** Fields related to POSIX data types

-- | Creates a new mandatory field that reads a file mode in the standard
-- POSIX file mode representation. The Haskell type of the field is 'FileMode'.
fileModeAsIntField :: String -> Field
fileModeAsIntField = integralField [t| FileMode |]

-- | Creates a new mandatory field that contains a POSIX process ID.
processIdField :: String -> Field
processIdField = integralField [t| ProcessID |]
