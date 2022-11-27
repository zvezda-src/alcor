{-| Implementation of the Alcor Query2 export queries.

 -}

{-
-}

module Alcor.Query.Export
  ( Runtime
  , fieldsMap
  , collectLiveData
  ) where

import Control.Monad (liftM)

import Alcor.Objects
import Alcor.Rpc
import Alcor.Query.Language
import Alcor.Query.Common
import Alcor.Query.Types

-- | The parsed result of the ExportList. This is a bit tricky, in
-- that we already do parsing of the results in the RPC calls, so the
-- runtime type is a plain 'ResultEntry', as we have just one type.
type Runtime = ResultEntry

-- | Small helper for rpc to rs.
rpcErrToRs :: RpcError -> ResultEntry
rpcErrToRs err = ResultEntry (rpcErrorToStatus err) Nothing

-- | Helper for extracting fields from RPC result.
rpcExtractor :: Node -> Either RpcError RpcResultExportList
             -> [(Node, ResultEntry)]
rpcExtractor node (Right res) =
  [(node, rsNormal path) | path <- rpcResExportListExports res]
rpcExtractor node (Left err)  = [(node, rpcErrToRs err)]

-- | List of all node fields.
exportFields :: FieldList Node Runtime
exportFields =
  [ (FieldDefinition "node" "Node" QFTText "Node name",
     FieldRuntime (\_ n -> rsNormal $ nodeName n), QffHostname)
  , (FieldDefinition "export" "Export" QFTText "Export name",
     FieldRuntime (curry fst), QffNormal)
  ]

-- | The node fields map.
fieldsMap :: FieldMap Node Runtime
fieldsMap = fieldListToFieldMap exportFields

-- | Collect live data from RPC query if enabled.
--
-- Note that this function is \"funny\": the returned rows will not be
-- 1:1 with the input, as nodes without exports will be pruned,
-- whereas nodes with multiple exports will be listed multiple times.
collectLiveData:: Bool -> ConfigData -> [Node] -> IO [(Node, Runtime)]
collectLiveData False _ nodes =
  return [(n, rpcErrToRs $ RpcResultError "Live data disabled") | n <- nodes]
collectLiveData True _ nodes =
  concatMap (uncurry rpcExtractor) `liftM`
    executeRpcCall nodes RpcCallExportList
