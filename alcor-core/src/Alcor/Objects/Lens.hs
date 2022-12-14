{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE LiberalTypeSynonyms #-}

{-| Lenses for Alcor config objects

-}

{-
-}

module Alcor.Objects.Lens where

import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import Control.Lens (Simple)
import Control.Lens.Iso (Iso, iso)
import qualified Data.Set as Set
import System.Time (ClockTime(..))

import Alcor.Lens (makeCustomLenses, Lens')
import Alcor.Objects

-- | Isomorphism between Strings and bytestrings
stringL :: Simple Iso BS.ByteString String
stringL = iso UTF8.toString UTF8.fromString

-- | Class of objects that have timestamps.
class TimeStampObject a => TimeStampObjectL a where
  mTimeL :: Lens' a ClockTime

-- | Class of objects that have an UUID.
class UuidObject a => UuidObjectL a where
  uuidL :: Lens' a String

-- | Class of object that have a serial number.
class SerialNoObject a => SerialNoObjectL a where
  serialL :: Lens' a Int

-- | Class of objects that have tags.
class TagsObject a => TagsObjectL a where
  tagsL :: Lens' a TagSet

$(makeCustomLenses ''AddressPool)

$(makeCustomLenses ''Network)

instance SerialNoObjectL Network where
  serialL = networkSerialL

instance TagsObjectL Network where
  tagsL = networkTagsL

instance UuidObjectL Network where
  uuidL = networkUuidL . stringL

instance TimeStampObjectL Network where
  mTimeL = networkMtimeL

$(makeCustomLenses ''PartialNic)

$(makeCustomLenses ''Disk)

instance TimeStampObjectL Disk where
  mTimeL = diskMtimeL

instance UuidObjectL Disk where
  uuidL = diskUuidL . stringL

instance SerialNoObjectL Disk where
  serialL = diskSerialL

$(makeCustomLenses ''Instance)

instance TimeStampObjectL Instance where
  mTimeL = instMtimeL

instance UuidObjectL Instance where
  uuidL = instUuidL . stringL

instance SerialNoObjectL Instance where
  serialL = instSerialL

instance TagsObjectL Instance where
  tagsL = instTagsL

$(makeCustomLenses ''MinMaxISpecs)

$(makeCustomLenses ''PartialIPolicy)

$(makeCustomLenses ''FilledIPolicy)

$(makeCustomLenses ''Node)

instance TimeStampObjectL Node where
  mTimeL = nodeMtimeL

instance UuidObjectL Node where
  uuidL = nodeUuidL . stringL

instance SerialNoObjectL Node where
  serialL = nodeSerialL

instance TagsObjectL Node where
  tagsL = nodeTagsL

$(makeCustomLenses ''NodeGroup)

instance TimeStampObjectL NodeGroup where
  mTimeL = groupMtimeL

instance UuidObjectL NodeGroup where
  uuidL = groupUuidL . stringL

instance SerialNoObjectL NodeGroup where
  serialL = groupSerialL

instance TagsObjectL NodeGroup where
  tagsL = groupTagsL

$(makeCustomLenses ''Cluster)

instance TimeStampObjectL Cluster where
  mTimeL = clusterMtimeL

instance UuidObjectL Cluster where
  uuidL = clusterUuidL . stringL

instance SerialNoObjectL Cluster where
  serialL = clusterSerialL

instance TagsObjectL Cluster where
  tagsL = clusterTagsL

$(makeCustomLenses ''ConfigData)

instance SerialNoObjectL ConfigData where
  serialL = configSerialL

instance TimeStampObjectL ConfigData where
  mTimeL = configMtimeL
