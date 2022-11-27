{-| External data loader.

This module holds the external data loading, and thus is the only one
depending (via the specialized Text\/Rapi\/Luxi modules) on the actual
libraries implementing the low-level protocols.

-}

{-
-}

module Alcor.HTools.ExtLoader
  ( loadExternalData
  , commonSuffix
  , maybeSaveData
  ) where

import Control.Monad
import Control.Monad.Writer (runWriterT)
import Control.Exception
import Data.Maybe (isJust, fromJust)
import Data.Monoid (getAll)
import System.FilePath
import System.IO
import System.Time (getClockTime)
import Text.Printf (hPrintf)

import Alcor.BasicTypes
import qualified Alcor.HTools.Backend.Luxi as Luxi
import qualified Alcor.HTools.Backend.Rapi as Rapi
import qualified Alcor.HTools.Backend.Simu as Simu
import qualified Alcor.HTools.Backend.Text as Text
import qualified Alcor.HTools.Backend.IAlloc as IAlloc
import qualified Alcor.HTools.Backend.MonD as MonD
import Alcor.HTools.CLI
import Alcor.HTools.Loader (mergeData, updateMissing, ClusterData(..)
                            , commonSuffix, clearDynU)
import Alcor.HTools.Types
import Alcor.Utils (sepSplit, tryRead, exitIfBad, exitWhen)

-- | Error beautifier.
wrapIO :: IO (Result a) -> IO (Result a)
wrapIO = handle (\e -> return . Bad . show $ (e::IOException))

-- | Parses a user-supplied utilisation string.
parseUtilisation :: String -> Result (String, DynUtil)
parseUtilisation line =
  case sepSplit ' ' line of
    [name, cpu, mem, dsk, net] ->
      do
        rcpu <- tryRead name cpu
        rmem <- tryRead name mem
        rdsk <- tryRead name dsk
        rnet <- tryRead name net
        let du = DynUtil { cpuWeight = rcpu, memWeight = rmem
                         , dskWeight = rdsk, netWeight = rnet }
        return (name, du)
    _ -> Bad $ "Cannot parse line " ++ line

-- | External tool data loader from a variety of sources.
loadExternalData :: Options
                 -> IO ClusterData
loadExternalData opts = do
  let mhost = optMaster opts
      lsock = optLuxi opts
      tfile = optDataFile opts
      simdata = optNodeSim opts
      iallocsrc = optIAllocSrc opts
      setRapi = mhost /= ""
      setLuxi = isJust lsock
      setSim = (not . null) simdata
      setFile = isJust tfile
      setIAllocSrc = isJust iallocsrc
      allSet = filter id [setRapi, setLuxi, setFile]
      exTags = case optExTags opts of
                 Nothing -> []
                 Just etl -> map (++ ":") etl
      selInsts = optSelInst opts
      exInsts = optExInst opts

  exitWhen (length allSet > 1) "Only one of the rapi, luxi, and data\
                               \ files options should be given."

  util_contents <- maybe (return "") readFile (optDynuFile opts)
  util_data <- exitIfBad "can't parse utilisation data" .
               mapM parseUtilisation $ lines util_contents
  input_data <-
    case () of
      _ | setRapi -> wrapIO $ Rapi.loadData mhost
        | setLuxi -> wrapIO . Luxi.loadData $ fromJust lsock
        | setSim -> Simu.loadData simdata
        | setFile -> wrapIO . Text.loadData $ fromJust tfile
        -- IAlloc.loadData calls updateMissing internally because Hail does not
        -- loadExternalData for loading the JSON config (see wrapReadRequest).
        -- Here we just pass a 0 as the 'generic' call to updateMissing follows.
        | setIAllocSrc -> wrapIO . flip IAlloc.loadData 0 $ fromJust iallocsrc
        | otherwise -> return $ Bad "No backend selected! Exiting."
  now <- getClockTime

  let ignoreDynU = optIgnoreDynu opts
      staticNodeMem = optStaticKvmNodeMemory opts
      eff_u = if ignoreDynU then [] else util_data
      ldresult = input_data >>= (if ignoreDynU then clearDynU else return)
                            >>= mergeData eff_u exTags selInsts exInsts now
  cdata <- exitIfBad "failed to load data, aborting" ldresult
  (cdata', ok) <- runWriterT $ if optMonD opts
                                 then MonD.queryAllMonDDCs cdata opts
                                 else return cdata
  exitWhen (optMonDExitMissing opts && not (getAll ok))
      "Not all required data available"
  let (fix_msgs, nl) = updateMissing (cdNodes cdata')
                                     (cdInstances cdata')
                                     staticNodeMem

  unless (optVerbose opts == 0) $ maybeShowWarnings fix_msgs

  return cdata' {cdNodes = nl}

-- | Function to save the cluster data to a file.
maybeSaveData :: Maybe FilePath -- ^ The file prefix to save to
              -> String         -- ^ The suffix (extension) to add
              -> String         -- ^ Informational message
              -> ClusterData    -- ^ The cluster data
              -> IO ()
maybeSaveData Nothing _ _ _ = return ()
maybeSaveData (Just path) ext msg cdata = do
  let adata = Text.serializeCluster cdata
      out_path = path <.> ext
  writeFile out_path adata
  hPrintf stderr "The cluster state %s has been written to file '%s'\n"
          msg out_path
