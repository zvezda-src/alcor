{-| PyValue contains instances for the 'PyValue' typeclass.

The typeclass 'PyValue' converts Haskell values to Python values.
This module contains instances of this typeclass for several generic
types.  These instances are used in the Haskell to Python generation
of opcodes and constants, for example.

-}

{-
-}
{-# LANGUAGE ExistentialQuantification #-}
module Alcor.PyValue
  ( PyValue(..)
  , PyValueEx(..)
  ) where

import Data.Char (isAscii, isPrint, ord)
import Data.List (intercalate)
import Data.Map (Map)
import Data.ByteString (ByteString)
import Text.Printf (printf)
import qualified Data.ByteString.Char8 as BC8 (foldr)
import qualified Data.Map as Map
import qualified Data.Set as Set (toList)

import Alcor.BasicTypes

-- * PyValue represents data types convertible to Python

-- | Converts Haskell values into Python values
--
-- This is necessary for the default values of opcode parameters and
-- return values.  For example, if a default value or return type is a
-- Data.Map, then it must be shown as a Python dictioanry.
class PyValue a where
  showValue :: a -> String

  showValueList :: [a] -> String
  showValueList xs =  "[" ++ intercalate "," (map showValue xs) ++ "]"

instance PyValue Bool where
  showValue = show

instance PyValue Int where
  showValue = show

instance PyValue Integer where
  showValue = show

instance PyValue Double where
  showValue = show

instance PyValue Char where
  showValue = show
  showValueList = show

-- (Byte)String show output does not work out of the box as a Python
-- string/bytes literal, especially when special characters are involved.
-- For instance, show ByteString.Char8.pack "\x03" yields "\ETX", which means
-- something completely different in Python. Thus, we need to implement our own
-- showValue, which does the following:
--  * escapes double quotes
--  * leaves all printable ASCII characters intact
--  * encodes all other characters in \xYZ form
instance PyValue ByteString where
  showValue bs =
    "b'" ++ (BC8.foldr (\c acc -> formatChar c ++ acc) "" bs) ++ "'"
    where
    formatChar x
      | x == '\\' = "\\\\"
      | x == '\'' = "\\\'"
      | isAscii x && isPrint x = [x]
      | otherwise = (printf "\\x%02x" $ ord x)

instance (PyValue a, PyValue b) => PyValue (a, b) where
  showValue (x, y) = "(" ++ showValue x ++ "," ++ showValue y ++ ")"

instance (PyValue a, PyValue b, PyValue c) => PyValue (a, b, c) where
  showValue (x, y, z) =
    "(" ++
    showValue x ++ "," ++
    showValue y ++ "," ++
    showValue z ++
    ")"

instance PyValue a => PyValue [a] where
  showValue = showValueList

instance (PyValue k, PyValue a) => PyValue (Map k a) where
  showValue mp =
    "{" ++ intercalate ", " (map showPair (Map.assocs mp)) ++ "}"
    where showPair (k, x) = showValue k ++ ":" ++ showValue x

instance PyValue a => PyValue (ListSet a) where
  showValue = showValue . Set.toList . unListSet

-- * PyValue represents an unspecified value convertible to Python

-- | Encapsulates Python default values
data PyValueEx = forall a. PyValue a => PyValueEx a

instance PyValue PyValueEx where
  showValue (PyValueEx x) = showValue x
