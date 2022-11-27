{-| IAllocator plugin for Alcor.

-}

{-
-}

module Alcor.HTools.Program.Hail
  ( main
  , options
  , arguments
  ) where

import Control.Monad
import Control.Monad.Writer (runWriterT)
import Data.Maybe (fromMaybe, isJust)
import System.IO

import qualified Alcor.HTools.AlgorithmParams as Alg
import qualified Alcor.HTools.Cluster as Cluster
import qualified Alcor.HTools.Dedicated as Dedicated

import Alcor.Common
import Alcor.HTools.CLI
import Alcor.HTools.Backend.IAlloc
import qualified Alcor.HTools.Backend.MonD as MonD
import Alcor.HTools.Loader (Request(..), ClusterData(..), isAllocationRequest)
import Alcor.HTools.ExtLoader (maybeSaveData, loadExternalData)
import Alcor.Utils

-- | Options list and functions.
options :: IO [OptType]
options =
  return
    [ oPrintNodes
    , oSaveCluster
    , oDataFile
    , oNodeSim
    , oVerbose
    , oIgnoreDyn
    , oIgnoreSoftErrors
    , oNoCapacityChecks
    , oRestrictToNodes
    , oMonD
    , oMonDXen
    , oStaticKvmNodeMemory
    ]

-- | The list of arguments supported by the program.
arguments :: [ArgCompletion]
arguments = [ArgCompletion OptComplFile 1 (Just 1)]

wrapReadRequest :: Options -> [String] -> IO Request
wrapReadRequest opts args = do
  let static_n_mem = optStaticKvmNodeMemory opts
  r1 <- case args of
          []    -> exitErr "This program needs an input file."
          _:_:_ -> exitErr "Only one argument is accepted (the input file)"
          x:_   -> readRequest x static_n_mem

  if isJust (optDataFile opts) ||  (not . null . optNodeSim) opts
    then do
      -- TODO: Cleanup this mess. ClusterData is loaded first in
      -- IAlloc.readRequest, then the data part is dropped and replaced with
      -- ExtLoader.loadExternalData that uses IAlloc.loadData to load the same
      -- data again. This codepath is executed only with a manually specified
      -- cluster data file or simulation (i.e. not under'normal' operation.)
      cdata <- loadExternalData opts
      let Request rqt _ = r1
      return $ Request rqt cdata
    else do
      let Request rqt cdata = r1
      (cdata', _) <- runWriterT $ if optMonD opts
                                    then MonD.queryAllMonDDCs cdata opts
                                    else return cdata
      return $ Request rqt cdata'

-- | Main function.
main :: Options -> [String] -> IO ()
main opts args = do
  let shownodes = optShowNodes opts
      verbose = optVerbose opts
      savecluster = optSaveCluster opts

  request <- wrapReadRequest opts args

  let Request rq cdata = request

  when (verbose > 1) .
       hPutStrLn stderr $ "Received request: " ++ show rq

  when (verbose > 2) .
       hPutStrLn stderr $ "Received cluster data: " ++ show cdata

  let dedicatedAlloc = maybe False (Dedicated.isDedicated cdata)
                       $ isAllocationRequest rq

  when (verbose > 1 && dedicatedAlloc) $
      hPutStrLn stderr "Allocation on a dedicated cluster;\
                       \ using lost-allocations metrics."

  maybePrintNodes shownodes "Initial cluster"
       (Cluster.printNodes (cdNodes cdata))

  maybeSaveData savecluster "pre-ialloc" "before iallocator run" cdata

  let runAlloc = if dedicatedAlloc
                   then Dedicated.runDedicatedAllocation
                   else runIAllocator
      (maybe_ni, resp) = runAlloc (Alg.fromCLIOptions opts) request
      (fin_nl, fin_il) = fromMaybe (cdNodes cdata, cdInstances cdata) maybe_ni
  putStrLn resp

  maybePrintNodes shownodes "Final cluster" (Cluster.printNodes fin_nl)

  maybeSaveData savecluster "post-ialloc" "after iallocator run"
       (cdata { cdNodes = fin_nl, cdInstances = fin_il})
