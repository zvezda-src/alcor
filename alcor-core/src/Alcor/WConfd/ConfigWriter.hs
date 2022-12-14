{-# LANGUAGE RankNTypes, FlexibleContexts #-}

{-| Implementation of functions specific to configuration management.

-}

{-
-}

module Alcor.WConfd.ConfigWriter
  ( loadConfigFromFile
  , readConfig
  , writeConfig
  , saveConfigAsyncTask
  , distMCsAsyncTask
  , distSSConfAsyncTask
  ) where

import Control.Monad.Base
import Control.Monad.Error
import qualified Control.Monad.State.Strict as S
import Control.Monad.Trans.Control
import Data.Monoid
import qualified Data.Set as Set

import Alcor.BasicTypes
import Alcor.Errors
import Alcor.Config
import Alcor.Logging
import Alcor.Objects
import Alcor.Rpc
import Alcor.Runtime
import Alcor.Utils
import Alcor.Utils.Atomic
import Alcor.Utils.AsyncWorker
import Alcor.WConfd.ConfigState
import Alcor.WConfd.Monad
import Alcor.WConfd.Ssconf

-- | From a distribution target get a predicate on nodes whether it
-- should be distributed to this node.
targetToPredicate :: DistributionTarget -> Node -> Bool
targetToPredicate Everywhere = const True
targetToPredicate (ToGroups gs) = (`Set.member` gs) . nodeGroup

-- | Loads the configuration from the file, if it hasn't been loaded yet.
-- The function is internal and isn't thread safe.
loadConfigFromFile :: FilePath
                   -> ResultG (ConfigData, FStat)
loadConfigFromFile path = withLockedFile path $ \_ -> do
    stat <- liftBase $ getFStat path
    cd <- mkResultT (loadConfig path)
    return (cd, stat)

-- | Writes the current configuration to the file. The function isn't thread
-- safe.
-- Neither distributes the configuration (to nodes and ssconf) nor
-- updates the serial number.
writeConfigToFile :: (MonadBase IO m, MonadError AlcorException m, MonadLog m)
                  => ConfigData -> FilePath -> FStat -> m FStat
writeConfigToFile cfg path oldstat = do
    logDebug $ "Async. config. writer: Commencing write\
               \ serial no " ++ show (serialOf cfg)
    r <- toErrorBase $ atomicUpdateLockedFile_ path oldstat doWrite
    logDebug "Async. config. writer: written"
    return r
  where
    doWrite fname fh = do
      setOwnerAndGroupFromNames fname AlcorWConfd
                                (DaemonGroup AlcorConfd)
      setOwnerWGroupR fname
      saveConfig fh cfg

-- Reads the current configuration state in the 'WConfdMonad'.
readConfig :: WConfdMonad ConfigData
readConfig = csConfigData <$> readConfigState

-- Replaces the current configuration state within the 'WConfdMonad'.
writeConfig :: ConfigData -> WConfdMonad ()
writeConfig cd = modifyConfigState $ const ((), mkConfigState cd)

-- * Asynchronous tasks

-- | Runs the given action on success, or logs an error on failure.
finishOrLog :: (Show e, MonadLog m)
            => Priority
            -> String
            -> (a -> m ())
            -> GenericResult e a
            -> m ()
finishOrLog logPrio logPrefix =
  genericResult (logAt logPrio . (++) (logPrefix ++ ": ") . show)

-- | Creates a stateless asynchronous task that handles errors in its actions.
mkStatelessAsyncTask :: (MonadBaseControl IO m, MonadLog m, Show e, Monoid i)
                     => Priority
                     -> String
                     -> (i -> ResultT e m ())
                     -> m (AsyncWorker i ())
mkStatelessAsyncTask logPrio logPrefix action =
    mkAsyncWorker $ runResultT . action
                    >=> finishOrLog logPrio logPrefix return

-- | Creates an asynchronous task that handles errors in its actions.
-- If an error occurs, it's logged and the internal state remains unchanged.
mkStatefulAsyncTask :: (MonadBaseControl IO m, MonadLog m, Show e, Monoid i)
                    => Priority
                    -> String
                    -> s
                    -> (s -> i -> ResultT e m s)
                    -> m (AsyncWorker i ())
mkStatefulAsyncTask logPrio logPrefix start action =
    flip S.evalStateT start . mkAsyncWorker $ \i ->
      S.get >>= lift . runResultT . flip action i
            >>= finishOrLog logPrio logPrefix S.put -- put on success

-- | Construct an asynchronous worker whose action is to save the
-- configuration to the master file.
-- The worker's action reads the configuration using the given @IO@ action
-- and uses 'FStat' to check if the configuration hasn't been modified by
-- another process.
--
-- If 'Any' of the input requests is true, given additional worker
-- will be executed synchronously after sucessfully writing the configuration
-- file. Otherwise, they'll be just triggered asynchronously.
saveConfigAsyncTask :: FilePath -- ^ Path to the config file
                    -> FStat  -- ^ The initial state of the config. file
                    -> IO ConfigState -- ^ An action to read the current config
                    -> [AsyncWorker DistributionTarget ()]
                    -- ^ Workers to be triggered afterwards
                    -> ResultG (AsyncWorker (Any, DistributionTarget) ())
saveConfigAsyncTask fpath fstat cdRef workers =
  lift . mkStatefulAsyncTask
           EMERGENCY "Can't write the master configuration file" fstat
       $ \oldstat (Any flush, target) -> do
            cd <- liftBase (csConfigData `liftM` cdRef)
            writeConfigToFile cd fpath oldstat
              <* if flush then logDebug "Running distribution synchronously"
                               >> triggerAndWaitMany target workers
                          else logDebug "Running distribution asynchronously"
                               >> mapM (trigger target) workers


-- | Performs a RPC call on the given list of nodes and logs any failures.
-- If any of the calls fails, fail the computation with 'failError'.
execRpcCallAndLog :: (Rpc a b) => [Node] -> a -> ResultG ()
execRpcCallAndLog nodes req = do
  rs <- liftIO $ executeRpcCall nodes req
  es <- logRpcErrors rs
  unless (null es) $ failError "At least one of the RPC calls failed"

-- | Construct an asynchronous worker whose action is to distribute the
-- configuration to master candidates.
distMCsAsyncTask :: RuntimeEnts
                 -> FilePath -- ^ Path to the config file
                 -> IO ConfigState -- ^ An action to read the current config
                 -> ResultG (AsyncWorker DistributionTarget ())
distMCsAsyncTask ents cpath cdRef =
  lift . mkStatelessAsyncTask ERROR "Can't distribute the configuration\
                                    \ to master candidates"
       $ \target -> do
          cd <- liftBase (csConfigData <$> cdRef) :: ResultG ConfigData
          logDebug $ "Distributing the configuration to master candidates,\
                     \ serial no " ++ show (serialOf cd) ++ ", " ++ show target
          fupload <- prepareRpcCallUploadFile ents cpath
          execRpcCallAndLog
            (filter (targetToPredicate target) $ getMasterCandidates cd) fupload
          logDebug "Successfully finished distributing the configuration"

-- | Construct an asynchronous worker whose action is to construct SSConf
-- and distribute it to master candidates.
-- The worker's action reads the configuration using the given @IO@ action,
-- computes the current SSConf, compares it to the previous version, and
-- if different, distributes it.
distSSConfAsyncTask
    :: IO ConfigState -- ^ An action to read the current config
    -> ResultG (AsyncWorker DistributionTarget ())
distSSConfAsyncTask cdRef =
  lift . mkStatefulAsyncTask ERROR "Can't distribute Ssconf" emptySSConf
       $ \oldssc target -> do
            cd <- liftBase (csConfigData <$> cdRef) :: ResultG ConfigData
            let ssc = mkSSConf cd
            if oldssc == ssc
              then logDebug "SSConf unchanged, not distributing"
              else do
                logDebug $ "Starting the distribution of SSConf\
                           \ serial no " ++ show (serialOf cd)
                           ++ ", " ++ show target
                execRpcCallAndLog (filter (targetToPredicate target)
                                    $ getOnlineNodes cd)
                                  (RpcCallWriteSsconfFiles ssc)
                logDebug "Successfully finished distributing SSConf"
            return ssc
