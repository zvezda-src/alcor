{-# LANGUAGE TemplateHaskell, FunctionalDependencies #-}

{-| Implementation of the Alcor Instance config object.

-}

{-
-}

module Alcor.Objects.Nic where

import qualified Data.ByteString.UTF8 as UTF8

import Alcor.THH
import Alcor.THH.Field
import Alcor.Types

$(buildParam "Nic" "nicp"
  [ simpleField "mode" [t| NICMode |]
  , simpleField "link" [t| String  |]
  , simpleField "vlan" [t| String |]
  ])

$(buildObject "PartialNic" "nic" $
  [ simpleField "mac" [t| String |]
  , optionalField $ simpleField "ip" [t| String |]
  , simpleField "nicparams" [t| PartialNicParams |]
  , optionalField $ simpleField "network" [t| String |]
  , optionalField $ simpleField "name" [t| String |]
  ] ++ uuidFields)

instance UuidObject PartialNic where
  uuidOf = UTF8.toString . nicUuid


