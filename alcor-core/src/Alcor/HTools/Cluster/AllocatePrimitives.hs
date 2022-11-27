{-| Implementation of the primitives of instance allocation

-}

{-
-}

module Alcor.HTools.Cluster.AllocatePrimitives
  ( allocateOnSingle
  , allocateOnPair
  ) where

import Alcor.HTools.AlgorithmParams (AlgorithmOptions(..))
import Alcor.HTools.Cluster.AllocationSolution (AllocElement)
import Alcor.HTools.Cluster.Metrics ( compCV, compCVfromStats
                                     , updateClusterStatisticsTwice)
import Alcor.HTools.Cluster.Moves (setInstanceLocationScore)
import qualified Alcor.HTools.Container as Container
import qualified Alcor.HTools.Instance as Instance
import qualified Alcor.HTools.Node as Node
import Alcor.HTools.Types
import Alcor.Utils.Statistics

-- | Tries to allocate an instance on one given node.
allocateOnSingle :: AlgorithmOptions
                 -> Node.List -> Instance.Instance -> Ndx
                 -> OpResult AllocElement
allocateOnSingle opts nl inst new_pdx =
  let p = Container.find new_pdx nl
      new_inst = Instance.setBoth inst new_pdx Node.noSecondary
      force = algIgnoreSoftErrors opts
  in do
    Instance.instMatchesPolicy inst (Node.iPolicy p) (Node.exclStorage p)
    new_p <- Node.addPriEx force p inst
    let new_nl = Container.add new_pdx new_p nl
        new_score = compCV new_nl
    return (new_nl, new_inst, [new_p], new_score)

-- | Tries to allocate an instance on a given pair of nodes.
allocateOnPair :: AlgorithmOptions
               -> [Statistics]
               -> Node.List -> Instance.Instance -> Ndx -> Ndx
               -> OpResult AllocElement
allocateOnPair opts stats nl inst new_pdx new_sdx =
  let tgt_p = Container.find new_pdx nl
      tgt_s = Container.find new_sdx nl
      force = algIgnoreSoftErrors opts
  in do
    Instance.instMatchesPolicy inst (Node.iPolicy tgt_p)
      (Node.exclStorage tgt_p)
    let new_inst = Instance.setBoth (setInstanceLocationScore inst tgt_p
                                                              (Just tgt_s))
                   new_pdx new_sdx
    new_p <- Node.addPriEx force tgt_p new_inst
    new_s <- Node.addSec tgt_s new_inst new_pdx
    let new_nl = Container.addTwo new_pdx new_p new_sdx new_s nl
        new_stats = updateClusterStatisticsTwice stats
                      (tgt_p, new_p) (tgt_s, new_s)
    return (new_nl, new_inst, [new_p, new_s], compCVfromStats new_stats)
