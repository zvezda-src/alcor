{-| Implementation of the Alcor Query2 cluster queries.

 -}

{-
-}

module Alcor.Query.Cluster
  ( clusterMasterNodeName
  , isWatcherPaused
  ) where

import Control.Exception (try)
import Control.Monad (liftM)
import Data.Char (isSpace)
import Numeric (readDec)

import Alcor.Config
import Alcor.Errors
import Alcor.Logging
import Alcor.Objects
import Alcor.Path
import Alcor.Utils (getCurrentTime)

-- | Get master node name.
clusterMasterNodeName :: ConfigData -> ErrorResult String
clusterMasterNodeName cfg =
  let cluster = configCluster cfg
      masterNodeUuid = clusterMasterNode cluster
  in liftM nodeName $ getNode cfg masterNodeUuid

isWatcherPaused :: IO (Maybe Integer)
isWatcherPaused = do
  logDebug "Checking if the watcher is paused"
  wfile <- watcherPauseFile
  contents <- try $ readFile wfile :: IO (Either IOError String)
  case contents of
    Left _ -> return Nothing
    Right s -> case readDec (dropWhile isSpace s) of
                 [(n, rest)] | all isSpace rest -> do
                   now <- getCurrentTime
                   return $ if n > now then Just n else Nothing
                 _ -> do
                   logWarning $ "Watcher pause file contents '" ++ s
                                 ++ "' not parsable as int"
                   return Nothing
