{-| Implementation of the Alcor Query2 node group queries.

 -}

{-
-}

module Alcor.Query.Group
  (fieldsMap) where

import Data.Maybe (mapMaybe)

import Alcor.Config
import Alcor.Objects
import Alcor.Query.Language
import Alcor.Query.Common
import Alcor.Query.Types
import Alcor.Utils (niceSort)

groupFields :: FieldList NodeGroup NoDataRuntime
groupFields =
  [ (FieldDefinition "alloc_policy" "AllocPolicy" QFTText
       "Allocation policy for group",
     FieldSimple (rsNormal . groupAllocPolicy), QffNormal)
  , (FieldDefinition "custom_diskparams" "CustomDiskParameters" QFTOther
       "Custom disk parameters",
     FieldSimple (rsNormal . groupDiskparams), QffNormal)
  , (FieldDefinition "custom_ipolicy" "CustomInstancePolicy" QFTOther
       "Custom instance policy limitations",
     FieldSimple (rsNormal . groupIpolicy), QffNormal)
  , (FieldDefinition "custom_ndparams" "CustomNDParams" QFTOther
       "Custom node parameters",
     FieldSimple (rsNormal . groupNdparams), QffNormal)
  , (FieldDefinition "diskparams" "DiskParameters" QFTOther
       "Disk parameters (merged)",
     FieldConfig (\cfg -> rsNormal . getGroupDiskParams cfg), QffNormal)
  , (FieldDefinition "ipolicy" "InstancePolicy" QFTOther
       "Instance policy limitations (merged)",
     FieldConfig (\cfg ng -> rsNormal (getGroupIpolicy cfg ng)), QffNormal)
  , (FieldDefinition "name" "Group" QFTText "Group name",
     FieldSimple (rsNormal . groupName), QffNormal)
  , (FieldDefinition "ndparams" "NDParams" QFTOther "Node parameters",
     FieldConfig (\cfg ng -> rsNormal (getGroupNdParams cfg ng)), QffNormal)
  , (FieldDefinition "node_cnt" "Nodes" QFTNumber "Number of nodes",
     FieldConfig (\cfg -> rsNormal . length . getGroupNodes cfg . uuidOf),
     QffNormal)
  , (FieldDefinition "node_list" "NodeList" QFTOther "List of nodes",
     FieldConfig (\cfg -> rsNormal . map nodeName .
                          getGroupNodes cfg . uuidOf), QffNormal)
  , (FieldDefinition "pinst_cnt" "Instances" QFTNumber
       "Number of primary instances",
     FieldConfig
       (\cfg -> rsNormal . length . fst . getGroupInstances cfg . uuidOf),
     QffNormal)
  , (FieldDefinition "pinst_list" "InstanceList" QFTOther
       "List of primary instances",
     FieldConfig (\cfg -> rsNormal . niceSort . mapMaybe instName . fst .
                          getGroupInstances cfg . uuidOf), QffNormal)
  ] ++
  map buildNdParamField allNDParamFields ++
  timeStampFields ++
  uuidFields "Group" ++
  serialFields "Group" ++
  tagsFields

-- | The group fields map.
fieldsMap :: FieldMap NodeGroup NoDataRuntime
fieldsMap = fieldListToFieldMap groupFields
