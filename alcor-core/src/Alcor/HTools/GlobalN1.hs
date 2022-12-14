{-| Implementation of global N+1 redundancy

-}

{-
-}

module Alcor.HTools.GlobalN1
  ( canEvacuateNode
  , redundant
  , redundantGrp
  , allocGlobalN1
  ) where

import Control.Monad (foldM, foldM_)
import qualified Data.Foldable as Foldable
import Data.Function (on)
import Data.List (partition, sortBy)

import Alcor.BasicTypes (isOk, Result)
import Alcor.HTools.AlgorithmParams (AlgorithmOptions(..), defaultOptions)
import Alcor.HTools.Cluster.AllocatePrimitives (allocateOnSingle)
import qualified Alcor.HTools.Cluster.AllocationSolution as AllocSol
import qualified Alcor.HTools.Cluster.Evacuate as Evacuate
import Alcor.HTools.Cluster.Moves (move)
import qualified Alcor.HTools.Container as Container
import qualified Alcor.HTools.Instance as Instance
import qualified Alcor.HTools.Node as Node
import Alcor.HTools.Types ( IMove(Failover), Ndx, Gdx, Idx, opToResult,
                             FailMode(FailN1) )
import Alcor.Types ( DiskTemplate(DTDrbd8), diskTemplateMovable
                    , EvacMode(ChangePrimary))

-- | Foldable function describing how a non-DRBD instance
-- is to be evacuated.
evac :: Gdx -> [Ndx]
     -> (Node.List, Instance.List) -> Idx -> Result (Node.List, Instance.List)
evac gdx ndxs (nl, il) idx = do
  let opts = defaultOptions { algIgnoreSoftErrors = True, algEvacMode = True }
      inst = Container.find idx il
  (nl', il', _) <- Evacuate.nodeEvacInstance opts nl il ChangePrimary inst
                     gdx ndxs
  return (nl', il')

-- | Foldable function describing how a non-movable instance is to
-- be recreated on one of the given nodes.
recreate :: [Ndx]
         -> (Node.List, Instance.List)
         -> Instance.Instance
         -> Result (Node.List, Instance.List)
recreate targetnodes (nl, il) inst = do
  let opts = defaultOptions { algIgnoreSoftErrors = True, algEvacMode = True }
      sols = foldl (\cstate ->
                       AllocSol.concatAllocCollections cstate
                       . allocateOnSingle opts nl inst
                   ) AllocSol.emptyAllocCollection targetnodes
      sol = AllocSol.collectionToSolution FailN1 (const True) sols
  alloc <- maybe (fail "No solution found") return $ AllocSol.asSolution sol
  let il' = AllocSol.updateIl il $ Just alloc
      nl' = AllocSol.extractNl nl il $ Just alloc
  return (nl', il')

-- | Decide if a node can be evacuated, i.e., all DRBD instances
-- failed over and all shared/external storage instances moved off
-- to other nodes.
canEvacuateNode :: (Node.List, Instance.List) -> Node.Node -> Bool
canEvacuateNode (nl, il) n = isOk $ do
  let (drbdIdxs, otherIdxs) = partition ((==) DTDrbd8
                                         . Instance.diskTemplate
                                         . flip Container.find il)
                              $ Node.pList n
      (sharedIdxs, nonMoveIdxs) = partition (diskTemplateMovable
                                  . Instance.diskTemplate
                                  . flip Container.find il) otherIdxs
  -- failover all DRBD instances with primaries on n
  (nl', il') <- opToResult
                . foldM move (nl, il) $ map (flip (,) Failover) drbdIdxs
  -- evacuate other instances
  let grp = Node.group n
      escapenodes = filter (/= Node.idx n)
                    . map Node.idx
                    . filter ((== grp) . Node.group)
                    $ Container.elems nl'
  (nl'', il'') <- foldM (evac grp escapenodes) (nl',il') sharedIdxs
  let recreateInstances = sortBy (flip compare `on` Instance.mem)
                          $ map (`Container.find` il'') nonMoveIdxs
  foldM_ (recreate escapenodes) (nl'', il'') recreateInstances

-- | Predicate on wheter a given situation is globally N+1 redundant.
redundant :: AlgorithmOptions -> Node.List -> Instance.List -> Bool
redundant opts nl il =
  let filterFun = if algAcceptExisting opts
                    then Container.filter (not . Node.offline)
                    else id
  in Foldable.all (canEvacuateNode (nl, il))
       . Container.filter (not . (`elem` algCapacityIgnoreGroups opts)
                               . Node.group)
       $ filterFun nl

-- | Predicate on wheter a given group is globally N+1 redundant.
redundantGrp :: AlgorithmOptions -> Node.List -> Instance.List -> Gdx -> Bool
redundantGrp opts nl il gdx =
  redundant opts (Container.filter ((==) gdx . Node.group) nl) il

-- | Predicate on wheter an allocation element leads to a globally N+1 redundant
-- state.
allocGlobalN1 :: AlgorithmOptions
              -> Node.List -- ^ the original list of nodes
              -> Instance.List -- ^ the original list of instances
              -> AllocSol.GenericAllocElement a -> Bool
allocGlobalN1 opts nl il alloc =
  let il' = AllocSol.updateIl il $ Just alloc
      nl' = AllocSol.extractNl nl il $ Just alloc
  in redundant opts nl' il'
