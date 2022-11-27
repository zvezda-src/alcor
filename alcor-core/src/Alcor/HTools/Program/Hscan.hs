{-| Scan clusters via RAPI or LUXI and write state data files.

-}

{-
-}

module Alcor.HTools.Program.Hscan
  ( main
  , options
  , arguments
  ) where

import Control.Monad
import Data.Maybe (isJust, fromJust, fromMaybe)
import System.Exit
import System.IO
import System.FilePath
import System.Time

import Text.Printf (printf)

import Alcor.BasicTypes
import qualified Alcor.HTools.Container as Container
import qualified Alcor.HTools.Cluster as Cluster
import qualified Alcor.HTools.Cluster.Metrics as Metrics
import qualified Alcor.HTools.Node as Node
import qualified Alcor.HTools.Instance as Instance
import qualified Alcor.HTools.Backend.Rapi as Rapi
import qualified Alcor.HTools.Backend.Luxi as Luxi
import qualified Alcor.Path as Path
import Alcor.HTools.Loader (updateMissing, mergeData, ClusterData(..))
import Alcor.HTools.Backend.Text (serializeCluster)

import Alcor.Common
import Alcor.HTools.CLI

-- | Options list and functions.
options :: IO [OptType]
options = do
  luxi <- oLuxiSocket
  return
    [ oPrintNodes
    , oOutputDir
    , luxi
    , oVerbose
    , oNoHeaders
    , oStaticKvmNodeMemory
    ]

-- | The list of arguments supported by the program.
arguments :: [ArgCompletion]
arguments = [ArgCompletion OptComplHost 0 Nothing]

-- | Return a one-line summary of cluster state.
printCluster :: Node.List -> Instance.List
             -> String
printCluster nl il =
  let (bad_nodes, bad_instances) = Cluster.computeBadItems nl il
      ccv = Metrics.compCV nl
      nodes = Container.elems nl
      insts = Container.elems il
      t_ram = sum . map Node.tMem $ nodes
      t_dsk = sum . map Node.tDsk $ nodes
      f_ram = sum . map Node.fMem $ nodes
      f_dsk = sum . map Node.fDsk $ nodes
  in printf "%5d %5d %5d %5d %6.0f %6d %6.0f %6d %.8f"
       (length nodes) (length insts)
       (length bad_nodes) (length bad_instances)
       t_ram f_ram (t_dsk / 1024) (f_dsk `div` 1024) ccv

-- | Replace slashes with underscore for saving to filesystem.
fixSlash :: String -> String
fixSlash = map (\x -> if x == '/' then '_' else x)

-- | Generates serialized data from loader input.
processData :: ClockTime -> ClusterData -> Int -> Result ClusterData
processData now input_data static_n_mem = do
  cdata@(ClusterData _ nl il _ _) <- mergeData [] [] [] [] now input_data
  let (_, fix_nl) = updateMissing nl il static_n_mem
  return cdata { cdNodes = fix_nl }

-- | Writes cluster data out.
writeData :: Int
          -> String
          -> Options
          -> Result ClusterData
          -> IO Bool
writeData _ name _ (Bad err) =
  printf "\nError for %s: failed to load data. Details:\n%s\n" name err >>
  return False

writeData nlen name opts (Ok cdata) = do
  now <- getClockTime
  let static_n_mem = optStaticKvmNodeMemory opts
      fixdata = processData now cdata static_n_mem
  case fixdata of
    Bad err -> printf "\nError for %s: failed to process data. Details:\n%s\n"
               name err >> return False
    Ok processed -> writeDataInner nlen name opts cdata processed

-- | Inner function for writing cluster data to disk.
writeDataInner :: Int
               -> String
               -> Options
               -> ClusterData
               -> ClusterData
               -> IO Bool
writeDataInner nlen name opts cdata fixdata = do
  let (ClusterData _ nl il _ _) = fixdata
  printf "%-*s " nlen name :: IO ()
  hFlush stdout
  let shownodes = optShowNodes opts
      odir = optOutPath opts
      oname = odir </> fixSlash name
  putStrLn $ printCluster nl il
  hFlush stdout
  when (isJust shownodes) .
       putStr $ Cluster.printNodes nl (fromJust shownodes)
  writeFile (oname <.> "data") (serializeCluster cdata)
  return True

-- | Main function.
main :: Options -> [String] -> IO ()
main opts clusters = do
  let local = "LOCAL"

  let nlen = if null clusters
             then length local
             else maximum . map length $ clusters

  unless (optNoHeaders opts) $
         printf "%-*s %5s %5s %5s %5s %6s %6s %6s %6s %10s\n" nlen
                "Name" "Nodes" "Inst" "BNode" "BInst" "t_mem" "f_mem"
                "t_disk" "f_disk" "Score"

  when (null clusters) $ do
         def_socket <- Path.defaultQuerySocket
         let lsock = fromMaybe def_socket (optLuxi opts)
         let name = local
         input_data <- Luxi.loadData lsock
         result <- writeData nlen name opts input_data
         unless result . exitWith $ ExitFailure 2

  results <- mapM (\name -> Rapi.loadData name >>= writeData nlen name opts)
             clusters
  unless (and results) $ exitWith (ExitFailure 2)
