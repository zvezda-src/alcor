{-| Implementation of Alcor filter queries.

-}

{-
-}

module Alcor.Query.FilterRules
  ( fieldsMap
  ) where

import Alcor.Objects
import Alcor.Query.Common
import Alcor.Query.Language
import Alcor.Query.Types


-- | List of all lock fields.
filterFields :: FieldList FilterRule NoDataRuntime
filterFields =
  [ (FieldDefinition "watermark" "Watermark" QFTOther "Highest job ID used\
                                                       \ at the time when the\
                                                       \ filter was added",
     FieldSimple (rsNormal . frWatermark), QffNormal)
  , (FieldDefinition "priority" "Priority" QFTOther "Filter priority",
     FieldSimple (rsNormal . frPriority), QffNormal)
  , (FieldDefinition "predicates" "Predicates" QFTOther "List of filter\
                                                         \ predicates",
     FieldSimple (rsNormal . frPredicates), QffNormal)
  , (FieldDefinition "action" "Action" QFTOther "Filter action",
     FieldSimple (rsNormal . frAction), QffNormal)
  , (FieldDefinition "reason_trail" "ReasonTrail" QFTOther "Reason why this\
                                                            \ filter was\
                                                            \ added",
     FieldSimple (rsNormal . frReasonTrail), QffNormal)
  , (FieldDefinition "uuid" "UUID" QFTOther "Filter ID",
     FieldSimple (rsNormal . frUuid), QffNormal)
  ]

-- | The lock fields map.
fieldsMap :: FieldMap FilterRule NoDataRuntime
fieldsMap = fieldListToFieldMap filterFields
