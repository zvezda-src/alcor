{-| Implementation of DataCollectors CLI functions.

This module holds the common command-line related functions for the
collector binaries.

-}

{-
-}

module Alcor.DataCollectors.CLI
  ( Options(..)
  , OptType
  , defaultOptions
  -- * The options
  , oShowHelp
  , oShowVer
  , oShowComp
  , oDrbdPairing
  , oDrbdStatus
  , oNode
  , oConfdAddr
  , oConfdPort
  , oInputFile
  , oInstances
  , genericOptions
  ) where

import System.Console.GetOpt

import Alcor.BasicTypes
import Alcor.Common as Common
import Alcor.Utils


-- * Data types

-- | Command line options structure.
data Options = Options
  { optShowHelp    :: Bool           -- ^ Just show the help
  , optShowComp    :: Bool           -- ^ Just show the completion info
  , optShowVer     :: Bool           -- ^ Just show the program version
  , optDrbdStatus  :: Maybe FilePath -- ^ Path to the file containing DRBD
                                     -- status information
  , optDrbdPairing :: Maybe FilePath -- ^ Path to the file containing pairings
                                     -- between instances and DRBD minors
  , optNode        :: Maybe String   -- ^ Info are requested for this node
  , optConfdAddr   :: Maybe String   -- ^ IP address of the Confd server
  , optConfdPort   :: Maybe Int      -- ^ The port of the Confd server to
                                     -- connect to
  , optInputFile   :: Maybe FilePath -- ^ Path to the file containing the
                                     -- information to be parsed
  , optInstances   :: Maybe FilePath -- ^ Path to the file contained a
                                     -- serialized list of instances as in:
                                     -- ([Primary], [Secondary])
  } deriving Show

-- | Default values for the command line options.
defaultOptions :: Options
defaultOptions  = Options
  { optShowHelp    = False
  , optShowComp    = False
  , optShowVer     = False
  , optDrbdStatus  = Nothing
  , optDrbdPairing = Nothing
  , optNode        = Nothing
  , optConfdAddr   = Nothing
  , optConfdPort   = Nothing
  , optInputFile   = Nothing
  , optInstances   = Nothing
  }

-- | Abbreviation for the option type.
type OptType = GenericOptType Options

instance StandardOptions Options where
  helpRequested = optShowHelp
  verRequested  = optShowVer
  compRequested = optShowComp
  requestHelp o = o { optShowHelp = True }
  requestVer  o = o { optShowVer  = True }
  requestComp o = o { optShowComp = True }

-- * Command line options
oDrbdPairing :: OptType
oDrbdPairing =
  ( Option "p" ["drbd-pairing"]
      (ReqArg (\ f o -> Ok o { optDrbdPairing = Just f}) "FILE")
      "the FILE containing pairings between instances and DRBD minors",
    OptComplFile)

oDrbdStatus :: OptType
oDrbdStatus =
  ( Option "s" ["drbd-status"]
      (ReqArg (\ f o -> Ok o { optDrbdStatus = Just f }) "FILE")
      "the DRBD status FILE",
    OptComplFile)

oNode :: OptType
oNode =
  ( Option "n" ["node"]
      (ReqArg (\ n o -> Ok o { optNode = Just n }) "NODE")
      "the FQDN of the NODE about which information is requested",
    OptComplFile)

oConfdAddr :: OptType
oConfdAddr =
  ( Option "a" ["address"]
      (ReqArg (\ a o -> Ok o { optConfdAddr = Just a }) "IP_ADDR")
      "the IP address of the Confd server to connect to",
    OptComplFile)

oConfdPort :: OptType
oConfdPort =
  (Option "p" ["port"]
    (reqWithConversion (tryRead "reading port")
      (\port opts -> Ok opts { optConfdPort = Just port }) "PORT")
    "Network port of the Confd server to connect to",
    OptComplInteger)

oInputFile :: OptType
oInputFile =
  ( Option "f" ["file"]
      (ReqArg (\ f o -> Ok o { optInputFile = Just f }) "FILE")
      "the input FILE",
    OptComplFile)

oInstances :: OptType
oInstances =
  ( Option "i" ["instances"]
      (ReqArg (\ f o -> Ok o { optInstances = Just f}) "FILE")
      "the FILE containing serialized instances",
    OptComplFile)

-- | Generic options.
genericOptions :: [GenericOptType Options]
genericOptions =  [ oShowVer
                  , oShowHelp
                  , oShowComp
                  ]
