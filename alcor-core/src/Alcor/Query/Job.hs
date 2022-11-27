{-| Implementation of the Alcor Query2 job queries.

 -}

{-
-}

module Alcor.Query.Job
  ( RuntimeData
  , fieldsMap
  , wantArchived
  ) where

import qualified Text.JSON as J

import Alcor.BasicTypes
import qualified Alcor.Constants as C
import Alcor.JQueue
import Alcor.Query.Common
import Alcor.Query.Language
import Alcor.Query.Types
import Alcor.Types

-- | The runtime data for a job.
type RuntimeData = Result (QueuedJob, Bool)

-- | Job priority explanation.
jobPrioDoc :: String
jobPrioDoc = "Current job priority (" ++ show C.opPrioLowest ++ " to " ++
             show C.opPrioHighest ++ ")"

-- | Timestamp doc.
tsDoc :: String -> String
tsDoc = (++ " (tuple containing seconds and microseconds)")

-- | Wrapper for unavailable job.
maybeJob :: (J.JSON a) =>
            (QueuedJob -> a) -> RuntimeData -> JobId -> ResultEntry
maybeJob _ (Bad _) _      = rsUnavail
maybeJob f (Ok (v, _))  _ = rsNormal $ f v

-- | Wrapper for optional fields that should become unavailable.
maybeJobOpt :: (J.JSON a) =>
            (QueuedJob -> Maybe a) -> RuntimeData -> JobId -> ResultEntry
maybeJobOpt _ (Bad _) _      = rsUnavail
maybeJobOpt f (Ok (v, _))  _ = case f v of
                                 Nothing -> rsUnavail
                                 Just w -> rsNormal w

-- | Simple helper for a job getter.
jobGetter :: (J.JSON a) => (QueuedJob -> a) -> FieldGetter JobId RuntimeData
jobGetter = FieldRuntime . maybeJob

-- | Simple helper for a per-opcode getter.
opsGetter :: (J.JSON a) => (QueuedOpCode -> a) -> FieldGetter JobId RuntimeData
opsGetter f = FieldRuntime $ maybeJob (map f . qjOps)

-- | Simple helper for a per-opcode optional field getter.
opsOptGetter :: (J.JSON a) =>
                (QueuedOpCode -> Maybe a) -> FieldGetter JobId RuntimeData
opsOptGetter f =
  FieldRuntime $ maybeJob (map (\qo -> case f qo of
                                         Nothing -> J.JSNull
                                         Just a -> J.showJSON a) . qjOps)

-- | Archived field name.
archivedField :: String
archivedField = "archived"

-- | Check whether we should look at archived jobs as well.
wantArchived :: [FilterField] -> Bool
wantArchived = (archivedField `elem`)

-- | List of all node fields. FIXME: QFF_JOB_ID on the id field.
jobFields :: FieldList JobId RuntimeData
jobFields =
  [ (FieldDefinition "id" "ID" QFTNumber "Job ID", FieldSimple rsNormal,
     QffNormal)
  , (FieldDefinition "status" "Status" QFTText "Job status",
     jobGetter calcJobStatus, QffNormal)
  , (FieldDefinition "priority" "Priority" QFTNumber jobPrioDoc,
     jobGetter calcJobPriority, QffNormal)
  , (FieldDefinition archivedField "Archived" QFTBool
       "Whether job is archived",
     FieldRuntime (\jinfo _ -> case jinfo of
                                 Ok (_, archive) -> rsNormal archive
                                 _ -> rsUnavail), QffNormal)
  , (FieldDefinition "ops" "OpCodes" QFTOther "List of all opcodes",
     opsGetter qoInput, QffNormal)
  , (FieldDefinition "opresult" "OpCode_result" QFTOther
       "List of opcodes results", opsGetter qoResult, QffNormal)
  , (FieldDefinition "opstatus" "OpCode_status" QFTOther
       "List of opcodes status", opsGetter qoStatus, QffNormal)
  , (FieldDefinition "oplog" "OpCode_log" QFTOther
       "List of opcode output logs", opsGetter qoLog, QffNormal)
  , (FieldDefinition "opstart" "OpCode_start" QFTOther
       "List of opcode start timestamps (before acquiring locks)",
     opsOptGetter qoStartTimestamp, QffNormal)
  , (FieldDefinition "opexec" "OpCode_exec" QFTOther
       "List of opcode execution start timestamps (after acquiring locks)",
     opsOptGetter qoExecTimestamp, QffNormal)
  , (FieldDefinition "opend" "OpCode_end" QFTOther
       "List of opcode execution end timestamps",
     opsOptGetter qoEndTimestamp, QffNormal)
  , (FieldDefinition "oppriority" "OpCode_prio" QFTOther
       "List of opcode priorities", opsGetter qoPriority, QffNormal)
  , (FieldDefinition "summary" "Summary" QFTOther
       "List of per-opcode summaries",
     opsGetter (extractOpSummary . qoInput), QffNormal)
  , (FieldDefinition "received_ts" "Received" QFTOther
       (tsDoc "Timestamp of when job was received"),
     FieldRuntime (maybeJobOpt qjReceivedTimestamp), QffTimestamp)
  , (FieldDefinition "start_ts" "Start" QFTOther
       (tsDoc "Timestamp of job start"),
     FieldRuntime (maybeJobOpt qjStartTimestamp), QffTimestamp)
  , (FieldDefinition "end_ts" "End" QFTOther
       (tsDoc "Timestamp of job end"),
     FieldRuntime (maybeJobOpt qjEndTimestamp), QffTimestamp)
  ]

-- | The node fields map.
fieldsMap :: FieldMap JobId RuntimeData
fieldsMap = fieldListToFieldMap jobFields
