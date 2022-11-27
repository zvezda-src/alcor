{-# LANGUAGE TemplateHaskell, FunctionalDependencies #-}
{-# OPTIONS_GHC -O0 #-}
-- We have to disable optimisation here, as some versions of ghc otherwise
-- fail to compile this code, at least within reasonable memory limits (40g).

{-| Implementation of the Alcor Instance config object.

-}

{-
-}

module Alcor.Objects.Instance where

import qualified Data.ByteString.UTF8 as UTF8

import Alcor.JSON (emptyContainer)
import Alcor.Objects.Nic
import Alcor.THH
import Alcor.THH.Field
import Alcor.Types
import Alcor.Utils (parseUnitAssumeBinary)

$(buildParam "Be" "bep"
  [ specialNumericalField 'parseUnitAssumeBinary
      $ simpleField "minmem"      [t| Int  |]
  , specialNumericalField 'parseUnitAssumeBinary
      $ simpleField "maxmem"      [t| Int  |]
  , simpleField "vcpus"           [t| Int  |]
  , simpleField "auto_balance"    [t| Bool |]
  , simpleField "always_failover" [t| Bool |]
  , simpleField "spindle_use"     [t| Int  |]
  ])

$(buildObjectWithForthcoming "Instance" "inst" $
  [ simpleField "name"             [t| String             |]
  , simpleField "primary_node"     [t| String             |]
  , simpleField "os"               [t| String             |]
  , simpleField "hypervisor"       [t| Hypervisor         |]
  , defaultField [| emptyContainer |]
      $ simpleField "hvparams"     [t| HvParams           |]
  , defaultField [| mempty |]
      $ simpleField "beparams"     [t| PartialBeParams    |]
  , defaultField [| emptyContainer |]
      $ simpleField "osparams"     [t| OsParams           |]
  , defaultField [| emptyContainer |]
      $ simpleField "osparams_private" [t| OsParamsPrivate |]
  , simpleField "admin_state"      [t| AdminState         |]
  , simpleField "admin_state_source" [t| AdminStateSource   |]
  , defaultField [| [] |]
      $ simpleField "nics"         [t| [PartialNic]       |]
  , defaultField [| [] |]
      $ simpleField "disks"        [t| [String]           |]
  , simpleField "disks_active"     [t| Bool               |]
  , optionalField $ simpleField "network_port" [t| Int  |]
  ]
  ++ timeStampFields
  ++ uuidFields
  ++ serialFields
  ++ tagsFields)

instance TimeStampObject Instance where
  cTimeOf = instCtime
  mTimeOf = instMtime

instance UuidObject Instance where
  uuidOf = UTF8.toString . instUuid

instance SerialNoObject Instance where
  serialOf = instSerial

instance TagsObject Instance where
  tagsOf = instTags

instance ForthcomingObject Instance where
  isForthcoming = instForthcoming
