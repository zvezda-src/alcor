{-| Implementation of finding a secondary for disk template conversion

-}

{-
-}

module Alcor.HTools.Cluster.AllocateSecondary
  ( tryAllocateSecondary
  ) where

import Control.Monad (unless)

import Alcor.BasicTypes
import Alcor.HTools.AlgorithmParams (AlgorithmOptions(..))
import qualified Alcor.HTools.Cluster as Cluster
import Alcor.HTools.Cluster.AllocationSolution (AllocSolution)
import qualified Alcor.HTools.Container as Container
import qualified Alcor.HTools.Group as Group
import qualified Alcor.HTools.Instance as Instance
import qualified Alcor.HTools.Node as Node
import Alcor.HTools.Types

tryAllocateSecondary :: AlgorithmOptions
                     -> Group.List    -- ^ The cluster groups
                     -> Node.List     -- ^ The node list (cluster-wide,
                                      -- not per group)
                     -> Instance.List -- ^ Instance list (cluster-wide)
                     -> Idx
                     -> Result AllocSolution
tryAllocateSecondary opts _ nl il idx = do
  let inst = Container.find idx il
  unless (Instance.sNode inst < 0)
    $ fail "Instance already has a secondary"
  let pidx = Instance.pNode inst
      pnode = Container.find pidx nl
      pnode' = Node.removePri pnode inst
      nl' = Container.add pidx pnode' nl
      inst' = inst { Instance.diskTemplate = DTDrbd8 }
      gidx = Node.group pnode'
      sidxs = filter (/= pidx) . Container.keys
              $ Container.filter ((==) gidx . Node.group) nl'
  Cluster.tryAlloc opts nl' il inst' $ Right [(pidx, sidxs)]
