{-| Converts a configuration state into a Ssconf map.

As TemplateHaskell require that splices be defined in a separate
module, we combine all the TemplateHaskell functionality that HTools
needs in this module (except the one for unittests).

-}

{-
-}

module Alcor.WConfd.Ssconf
  ( SSConf(..)
  , emptySSConf
  , mkSSConf
  ) where

import Control.Arrow ((&&&), (***), first)
import qualified Data.ByteString.UTF8 as UTF8
import Data.Foldable (Foldable(..), toList)
import Data.List (partition)
import Data.Maybe (mapMaybe)
import qualified Data.Map as M
import qualified Text.JSON as J

import Alcor.BasicTypes
import Alcor.Config
import Alcor.Constants
import Alcor.JSON (fromContainer, lookupContainer)
import Alcor.Objects
import Alcor.Ssconf
import Alcor.Utils
import Alcor.Types

eqPair :: (String, String) -> String
eqPair (x, y) = x ++ "=" ++ y

mkSSConfHvparams :: Cluster -> [(Hypervisor, [String])]
mkSSConfHvparams cluster = map (id &&& hvparams) [minBound..maxBound]
  where
    hvparams :: Hypervisor -> [String]
    hvparams h = maybe [] hvparamsStrings
                 $ lookupContainer Nothing h (clusterHvparams cluster)

    -- | Convert a collection of hypervisor parameters to strings in the form
    -- @key=value@.
    hvparamsStrings :: HvParams -> [String]
    hvparamsStrings =
      map (eqPair . (UTF8.toString *** hvparamShow)) . M.toList . fromContainer

    -- | Convert a hypervisor parameter in its JSON representation to a String.
    -- Strings, numbers and booleans are just printed (without quotes), booleans
    -- printed as @True@/@False@ and other JSON values (should they exist) as
    -- their JSON representations.
    hvparamShow :: J.JSValue -> String
    hvparamShow (J.JSString s) = J.fromJSString s
    hvparamShow (J.JSRational _ r) = J.showJSRational r []
    hvparamShow (J.JSBool b) = show b
    hvparamShow x = J.encode x

mkSSConf :: ConfigData -> SSConf
mkSSConf cdata = SSConf . M.fromList $
    [ (SSClusterName, return $ clusterClusterName cluster)
    , (SSClusterTags, toList . unTagSet $ tagsOf cluster)
    , (SSFileStorageDir, return $ clusterFileStorageDir cluster)
    , (SSSharedFileStorageDir, return $ clusterSharedFileStorageDir cluster)
    , (SSGlusterStorageDir, return $ clusterGlusterStorageDir cluster)
    , (SSMasterCandidates, mapLines nodeName mcs)
    , (SSMasterCandidatesIps, mapLines nodePrimaryIp mcs)
    , (SSMasterCandidatesCerts, mapLines eqPair . toPairs
                                . clusterCandidateCerts $ cluster)
    , (SSMasterIp, return $ clusterMasterIp cluster)
    , (SSMasterNetdev, return $ clusterMasterNetdev cluster)
    , (SSMasterNetmask, return . show $ clusterMasterNetmask cluster)
    , (SSMasterNode, return
                     . genericResult (const "NO MASTER") nodeName
                     . getNode cdata $ clusterMasterNode cluster)
    , (SSNodeList, mapLines nodeName nodes)
    , (SSNodePrimaryIps, mapLines (spcPair . (nodeName &&& nodePrimaryIp))
                                  nodes )
    , (SSNodeSecondaryIps, mapLines (spcPair . (nodeName &&& nodeSecondaryIp))
                                    nodes )
    , (SSNodeVmCapable,  mapLines (eqPair . (nodeName &&& show . nodeVmCapable))
                                  nodes)
    , (SSOfflineNodes, mapLines nodeName offline )
    , (SSOnlineNodes, mapLines nodeName online )
    , (SSPrimaryIpFamily, return . show . ipFamilyToRaw
                          . clusterPrimaryIpFamily $ cluster)
    , (SSInstanceList, niceSort . mapMaybe instName
                       . toList . configInstances $ cdata)
    , (SSReleaseVersion, return releaseVersion)
    , (SSHypervisorList, mapLines hypervisorToRaw
                         . clusterEnabledHypervisors $ cluster)
    , (SSMaintainNodeHealth, return . show . clusterMaintainNodeHealth
                             $ cluster)
    , (SSUidPool, mapLines formatUidRange . clusterUidPool $ cluster)
    , (SSNodegroups, mapLines (spcPair . (uuidOf &&& groupName))
                     nodeGroups)
    , (SSNetworks, mapLines (spcPair . (uuidOf
                                        &&& (fromNonEmpty . networkName)))
                   . configNetworks $ cdata)
    , (SSEnabledUserShutdown, return . show . clusterEnabledUserShutdown
                              $ cluster)
    , (SSSshPorts, mapLines (eqPair . (nodeName
                                       &&& getSshPort cdata)) nodes)
    ] ++
    map (first hvparamsSSKey) (mkSSConfHvparams cluster)
  where
    mapLines :: (Foldable f) => (a -> String) -> f a -> [String]
    mapLines f = map f . toList
    spcPair (x, y) = x ++ " " ++ y
    toPairs = M.assocs . M.mapKeys UTF8.toString . fromContainer

    cluster = configCluster cdata
    mcs = getMasterOrCandidates cdata
    nodes = niceSortKey nodeName . toList $ configNodes cdata
    (offline, online) = partition nodeOffline nodes
    nodeGroups = niceSortKey groupName . toList $ configNodegroups cdata

    -- This will return the empty string only for the situation where the
    -- configuration is corrupted and no nodegroup can be found for that node.
    getSshPort :: ConfigData -> Node -> String
    getSshPort cfg node = maybe "" (show . ndpSshPort)
                          $ getNodeNdParams cfg node
