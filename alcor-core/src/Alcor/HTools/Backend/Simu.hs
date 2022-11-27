{-| Parsing data from a simulated description of the cluster.

This module holds the code for parsing a cluster description.

-}

{-
-}

module Alcor.HTools.Backend.Simu
  ( loadData
  , parseData
  ) where

import Control.Monad (mplus, zipWithM)
import Text.Printf (printf)

import Alcor.BasicTypes
import Alcor.Utils
import Alcor.HTools.Types
import Alcor.HTools.Loader
import qualified Alcor.HTools.Container as Container
import qualified Alcor.HTools.Group as Group
import qualified Alcor.HTools.Node as Node

-- | Parse a shortened policy string (for command line usage).
apolAbbrev :: String -> Result AllocPolicy
apolAbbrev c | c == "p"  = return AllocPreferred
             | c == "a"  = return AllocLastResort
             | c == "u"  = return AllocUnallocable
             | otherwise = fail $ "Cannot parse AllocPolicy abbreviation '"
                           ++ c ++ "'"

-- | Parse the string description into nodes.
parseDesc :: String -> [String]
          -> Result (AllocPolicy, Int, Int, Int, Int, Int, Bool)
parseDesc _ [a, n, d, m, c, s, exstor] = do
  apol <- allocPolicyFromRaw a `mplus` apolAbbrev a
  ncount <- tryRead "node count" n
  disk <- annotateResult "disk size" (parseUnit d)
  mem <- annotateResult "memory size" (parseUnit m)
  cpu <- tryRead "cpu count" c
  spindles <- tryRead "spindles" s
  excl_stor <- tryRead "exclusive storage" exstor
  return (apol, ncount, disk, mem, cpu, spindles, excl_stor)

parseDesc desc [a, n, d, m, c] = parseDesc desc [a, n, d, m, c, "1"]

parseDesc desc [a, n, d, m, c, s] = parseDesc desc [a, n, d, m, c, s, "False"]

parseDesc desc es =
  fail $ printf
         "Invalid cluster specification, expected 6 comma-separated\
         \ sections (allocation policy, node count, disk size,\
         \ memory size, number of CPUs, spindles) but got %d: '%s'"
         (length es) desc

-- | Creates a node group with the given specifications.
createGroup :: Int    -- ^ The group index
            -> String -- ^ The group specification
            -> Result (Group.Group, [Node.Node])
createGroup grpIndex spec = do
  (apol, ncount, disk, mem, cpu, spindles, excl_stor) <- parseDesc spec $
                                                         sepSplit ',' spec
  let nodes = map (\idx ->
                    flip Node.setMaster (grpIndex == 1 && idx == 1) $
                    Node.create (printf "node-%02d-%03d" grpIndex idx)
                      (fromIntegral mem) 0 mem
                      (fromIntegral disk) disk
                      (fromIntegral cpu) 1 False spindles 0 grpIndex excl_stor
                  ) [1..ncount]
      -- TODO: parse networks to which this group is connected
      grp = Group.create (printf "group-%02d" grpIndex)
            (printf "fake-uuid-%02d" grpIndex) apol [] defIPolicy []
  return (Group.setIdx grp grpIndex, nodes)

-- | Builds the cluster data from node\/instance files.
parseData :: [String] -- ^ Cluster description in text format
          -> Result ClusterData
parseData ndata = do
  grpNodeData <- zipWithM createGroup [1..] ndata
  let (groups, nodes) = unzip grpNodeData
      nodes' = concat nodes
  let ktn = map (\(idx, n) -> (idx, Node.setIdx n idx))
            $ zip [1..] nodes'
      ktg = map (\g -> (Group.idx g, g)) groups
  return (ClusterData (Container.fromList ktg)
                      (Container.fromList ktn) Container.empty [] defIPolicy)

-- | Builds the cluster data from node\/instance files.
loadData :: [String] -- ^ Cluster description in text format
         -> IO (Result ClusterData)
loadData = -- IO monad, just for consistency with the other loaders
  return . parseData
