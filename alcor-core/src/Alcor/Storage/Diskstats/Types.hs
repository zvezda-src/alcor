{-# LANGUAGE TemplateHaskell #-}
{-| Diskstats data types

This module holds the definition of the data types describing the status of the
disks according to the information contained in @/proc/diskstats@.

-}
{-
-}
module Alcor.Storage.Diskstats.Types
  ( Diskstats(..)
  ) where

import Alcor.THH


-- | This is the format of the report produced by each data collector.
$(buildObject "Diskstats" "ds"
  [ simpleField "major"        [t| Int |]
  , simpleField "minor"        [t| Int |]
  , simpleField "name"         [t| String |]
  , simpleField "readsNum"        [t| Int |]
  , simpleField "mergedReads"  [t| Int |]
  , simpleField "secRead"      [t| Int |]
  , simpleField "timeRead"     [t| Int |]
  , simpleField "writes"       [t| Int |]
  , simpleField "mergedWrites" [t| Int |]
  , simpleField "secWritten"   [t| Int |]
  , simpleField "timeWrite"    [t| Int |]
  , simpleField "ios"          [t| Int |]
  , simpleField "timeIO"       [t| Int |]
  , simpleField "wIOmillis"    [t| Int |]
  ])
