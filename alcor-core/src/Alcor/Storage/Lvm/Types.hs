{-# LANGUAGE TemplateHaskell #-}
{-| LVM data types

This module holds the definition of the data types describing the status of the
disks according to LVM (and particularly the lvs tool).

-}
{-
-}
module Alcor.Storage.Lvm.Types
  ( LVInfo(..)
  ) where

import Alcor.THH


-- | This is the format of the report produced by each data collector.
$(buildObject "LVInfo" "lvi"
  [ simpleField "uuid"              [t| String |]
  , simpleField "name"              [t| String |]
  , simpleField "attr"              [t| String |]
  , simpleField "major"             [t| Int |]
  , simpleField "minor"             [t| Int |]
  , simpleField "kernel_major"      [t| Int |]
  , simpleField "kernel_minor"      [t| Int |]
  , simpleField "size"              [t| Int |]
  , simpleField "seg_count"         [t| Int |]
  , simpleField "tags"              [t| String |]
  , simpleField "modules"           [t| String |]
  , simpleField "vg_uuid"           [t| String |]
  , simpleField "vg_name"           [t| String |]
  , simpleField "segtype"           [t| String |]
  , simpleField "seg_start"         [t| Int |]
  , simpleField "seg_start_pe"      [t| Int |]
  , simpleField "seg_size"          [t| Int |]
  , simpleField "seg_tags"          [t| String |]
  , simpleField "seg_pe_ranges"     [t| String |]
  , simpleField "devices"           [t| String |]
  , optionalNullSerField $
    simpleField "instance"          [t| String |]
  ])
