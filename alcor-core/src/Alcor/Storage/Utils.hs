{-| Implementation of Utility functions for storage

 -}

{-
-}

module Alcor.Storage.Utils
  ( getStorageUnitsOfNode
  , nodesWithValidConfig
  ) where

import Alcor.Config
import Alcor.Objects
import Alcor.Types
import qualified Alcor.Types as T

import Control.Monad
import Data.List (nub)
import Data.Maybe

-- | Get the cluster's default storage unit for a given disk template
getDefaultStorageKey :: ConfigData -> DiskTemplate -> Maybe StorageKey
getDefaultStorageKey cfg T.DTDrbd8 = clusterVolumeGroupName $ configCluster cfg
getDefaultStorageKey cfg T.DTPlain = clusterVolumeGroupName $ configCluster cfg
getDefaultStorageKey cfg T.DTFile =
    Just (clusterFileStorageDir $ configCluster cfg)
getDefaultStorageKey _ _ = Nothing

-- | Get the cluster's default spindle storage unit
getDefaultSpindleSU :: ConfigData -> (StorageType, Maybe StorageKey)
getDefaultSpindleSU cfg =
    (T.StorageLvmPv, clusterVolumeGroupName $ configCluster cfg)

-- | Get the cluster's storage units from the configuration
getClusterStorageUnitRaws :: ConfigData -> [StorageUnitRaw]
getClusterStorageUnitRaws cfg =
    foldSUs (nub (maybe_units ++ [spindle_unit]))
  where disk_templates = clusterEnabledDiskTemplates $ configCluster cfg
        storage_types = map diskTemplateToStorageType disk_templates
        maybe_units = zip storage_types (map (getDefaultStorageKey cfg)
            disk_templates)
        spindle_unit = getDefaultSpindleSU cfg

-- | fold the storage unit list by sorting out the ones without keys
foldSUs :: [(StorageType, Maybe StorageKey)] -> [StorageUnitRaw]
foldSUs = foldr ff []
  where ff (st, Just sk) acc = SURaw st sk : acc
        ff (_, Nothing) acc = acc

-- | Gets the value of the 'exclusive storage' flag of the node
getExclusiveStorage :: ConfigData -> Node -> Maybe Bool
getExclusiveStorage cfg n = liftM ndpExclusiveStorage (getNodeNdParams cfg n)

-- | Determines whether a node's config contains an 'exclusive storage' flag
hasExclusiveStorageFlag :: ConfigData -> Node -> Bool
hasExclusiveStorageFlag cfg = isJust . getExclusiveStorage cfg

-- | Filter for nodes with a valid config
nodesWithValidConfig :: ConfigData -> [Node] -> [Node]
nodesWithValidConfig cfg = filter (hasExclusiveStorageFlag cfg)

-- | Get the storage units of the node
getStorageUnitsOfNode :: ConfigData -> Node -> [StorageUnit]
getStorageUnitsOfNode cfg n =
  let clusterSUs = getClusterStorageUnitRaws cfg
      es = fromJust (getExclusiveStorage cfg n)
  in  map (addParamsToStorageUnit es) clusterSUs
