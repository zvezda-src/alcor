{-| @/proc/diskstats@ data collector.

-}

{-
-}

module Alcor.DataCollectors.Diskstats
  ( main
  , options
  , arguments
  , dcName
  , dcVersion
  , dcFormatVersion
  , dcCategory
  , dcKind
  , dcReport
  ) where


import qualified Control.Exception as E
import Control.Monad
import Data.Attoparsec.Text.Lazy as A
import Data.Maybe
import Data.Text.Lazy (pack, unpack)
import qualified Text.JSON as J

import qualified Alcor.BasicTypes as BT
import qualified Alcor.Constants as C
import Alcor.Storage.Diskstats.Parser(diskstatsParser)
import Alcor.Common
import Alcor.DataCollectors.CLI
import Alcor.DataCollectors.Types
import Alcor.Utils


-- | The default path of the diskstats status file.
-- It is hardcoded because it is not likely to change.
defaultFile :: FilePath
defaultFile = C.diskstatsFile

-- | The default setting for the maximum amount of not parsed character to
-- print in case of error.
-- It is set to use most of the screen estate on a standard 80x25 terminal.
-- TODO: add the possibility to set this with a command line parameter.
defaultCharNum :: Int
defaultCharNum = 80*20

-- | The name of this data collector.
dcName :: String
dcName = C.dataCollectorDiskStats

-- | The version of this data collector.
dcVersion :: DCVersion
dcVersion = DCVerBuiltin

-- | The version number for the data format of this data collector.
dcFormatVersion :: Int
dcFormatVersion = 1

-- | The category of this data collector.
dcCategory :: Maybe DCCategory
dcCategory = Just DCStorage

-- | The kind of this data collector.
dcKind :: DCKind
dcKind = DCKPerf

-- | The data exported by the data collector, taken from the default location.
dcReport :: IO DCReport
dcReport = buildDCReport defaultFile

-- * Command line options

options :: IO [OptType]
options =
  return
    [ oInputFile
    ]

-- | The list of arguments supported by the program.
arguments :: [ArgCompletion]
arguments = [ArgCompletion OptComplFile 0 (Just 0)]

-- | This function computes the JSON representation of the diskstats status.
buildJsonReport :: FilePath -> IO J.JSValue
buildJsonReport inputFile = do
  contents <-
    ((E.try $ readFile inputFile) :: IO (Either IOError String)) >>=
      exitIfBad "reading from file" . either (BT.Bad . show) BT.Ok
  diskstatsData <-
    case A.parse diskstatsParser $ pack contents of
      A.Fail unparsedText contexts errorMessage -> exitErr $
        show (Prelude.take defaultCharNum $ unpack unparsedText) ++ "\n"
          ++ show contexts ++ "\n" ++ errorMessage
      A.Done _ diskstatsD -> return diskstatsD
  return $ J.showJSON diskstatsData

-- | This function computes the DCReport for the diskstats status.
buildDCReport :: FilePath -> IO DCReport
buildDCReport inputFile =
  buildJsonReport inputFile >>=
    buildReport dcName dcVersion dcFormatVersion dcCategory dcKind

-- | Main function.
main :: Options -> [String] -> IO ()
main opts args = do
  let inputFile = fromMaybe defaultFile $ optInputFile opts
  unless (null args) . exitErr $ "This program takes exactly zero" ++
                                  " arguments, got '" ++ unwords args ++ "'"
  report <- buildDCReport inputFile
  putStrLn $ J.encode report
