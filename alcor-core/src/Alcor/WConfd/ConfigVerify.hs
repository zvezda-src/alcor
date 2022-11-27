{-# LANGUAGE FlexibleContexts #-}

{-| Implementation of functions specific to configuration management.

-}

{-
-}

module Alcor.WConfd.ConfigVerify
  ( verifyConfig
  , verifyConfigErr
  ) where

import Control.Monad.Error
import qualified Data.ByteString.UTF8 as UTF8
import qualified Data.Foldable as F
import qualified Data.Map as M
import qualified Data.Set as S

import Alcor.Errors
import Alcor.JSON (GenericContainer(..), Container)
import Alcor.Objects
import Alcor.Types
import Alcor.Utils
import Alcor.Utils.Validate

-- * Configuration checks

-- | A helper function that returns the key set of a container.
keysSet :: (Ord k) => GenericContainer k v -> S.Set k
keysSet = M.keysSet . fromContainer

-- | Checks that all objects are indexed by their proper UUID.
checkUUIDKeys :: (UuidObject a, Show a)
              => String -> Container a -> ValidationMonad ()
checkUUIDKeys what = mapM_ check . M.toList . fromContainer
  where
    check (uuid, x) = reportIf (uuid /= UTF8.fromString (uuidOf x))
                      $ what ++ " '" ++ show x
                        ++ "' is indexed by wrong UUID '"
                        ++ UTF8.toString uuid ++ "'"

-- | Checks that all linked UUID of given objects exist.
checkUUIDRefs :: (UuidObject a, Show a, F.Foldable f)
              => String -> String
              -> (a -> [String]) -> f a -> Container b
              -> ValidationMonad ()
checkUUIDRefs whatObj whatTarget linkf xs targets = F.mapM_ check xs
  where
    uuids = keysSet targets
    check x = forM_ (linkf x) $ \uuid ->
                reportIf (not $ S.member (UTF8.fromString uuid) uuids)
                $ whatObj ++ " '" ++ show x ++ "' references a non-existing "
                  ++ whatTarget ++ " UUID '" ++ uuid ++ "'"

-- | Checks consistency of a given configuration.
--
-- TODO: Currently this implements only some very basic checks.
-- Evenually all checks from Python ConfigWriter need to be moved here
-- (see issue #759).
verifyConfig :: ConfigData -> ValidationMonad ()
verifyConfig cd = do
    let cluster = configCluster cd
        nodes = configNodes cd
        nodegroups = configNodegroups cd
        instances = configInstances cd
        networks = configNetworks cd
        disks = configDisks cd

    -- global cluster checks
    let enabledHvs = clusterEnabledHypervisors cluster
        hvParams = clusterHvparams cluster
    reportIf (null enabledHvs)
         "enabled hypervisors list doesn't have any entries"
    -- we don't need to check for invalid HVS as they would fail to parse
    let missingHvp = S.fromList enabledHvs S.\\ keysSet hvParams
    reportIf (not $ S.null missingHvp)
           $ "hypervisor parameters missing for the enabled hypervisor(s) "
             ++ (commaJoin . map hypervisorToRaw . S.toList $ missingHvp)

    let enabledDiskTemplates = clusterEnabledDiskTemplates cluster
    reportIf (null enabledDiskTemplates)
           "enabled disk templates list doesn't have any entries"
    -- we don't need to check for invalid templates as they wouldn't parse

    let masterNodeName = clusterMasterNode cluster
    reportIf (not $ UTF8.fromString masterNodeName
                       `S.member` keysSet (configNodes cd))
           $ "cluster has invalid primary node " ++ masterNodeName

    -- UUIDs
    checkUUIDKeys "node" nodes
    checkUUIDKeys "nodegroup" nodegroups
    checkUUIDKeys "instances" instances
    checkUUIDKeys "network" networks
    checkUUIDKeys "disk" disks
    -- UUID references
    checkUUIDRefs "node" "nodegroup" (return . nodeGroup) nodes nodegroups
    checkUUIDRefs "instance" "primary node" (maybe [] return . instPrimaryNode)
                                            instances nodes
    checkUUIDRefs "instance" "disks" instDisks instances disks

-- | Checks consistency of a given configuration.
-- If there is an error, throw 'ConfigVerifyError'.
verifyConfigErr :: (MonadError AlcorException m) => ConfigData -> m ()
verifyConfigErr cd =
  case runValidate $ verifyConfig cd of
    (_, []) -> return ()
    (_, es) -> throwError $ ConfigVerifyError "Validation failed" es
