{-# LANGUAGE FlexibleInstances, TypeSynonymInstances #-}
{-| Data types for Xen-specific hypervisor functionalities.

-}
{-
-}
module Alcor.Hypervisor.Xen.Types
  ( LispConfig(..)
  , Domain(..)
  , FromLispConfig(..)
  , UptimeInfo(..)
  , ActualState(..)
  ) where

import qualified Text.JSON as J

import Alcor.BasicTypes

-- | Data type representing configuration data as produced by the
-- @xl list --long@ command.
data LispConfig = LCList [LispConfig]
                | LCString String
                | LCDouble Double
                deriving (Eq, Show)

-- | Data type representing a Xen Domain.
data Domain = Domain
  { domId      :: Int
  , domName    :: String
  , domCpuTime :: Double
  , domState   :: ActualState
  , domIsHung  :: Maybe Bool
  } deriving (Show, Eq)

-- | Class representing all the types that can be extracted from LispConfig.
class FromLispConfig a where
  fromLispConfig :: LispConfig -> Result a

-- | Instance of FromLispConfig for Int.
instance FromLispConfig Int where
  fromLispConfig (LCDouble d) = Ok $ floor d
  fromLispConfig (LCList [LCString _, LCDouble d]) = Ok $ floor d
  fromLispConfig c =
    Bad $ "Unable to extract a Int from this configuration: "
      ++ show c

-- | Instance of FromLispConfig for Double.
instance FromLispConfig Double where
  fromLispConfig (LCDouble d) = Ok d
  fromLispConfig (LCList [LCString _, LCDouble d]) = Ok d
  fromLispConfig c =
    Bad $ "Unable to extract a Double from this configuration: "
      ++ show c

-- | Instance of FromLispConfig for String
instance FromLispConfig String where
  fromLispConfig (LCString s) = Ok s
  fromLispConfig (LCList [LCString _, LCString s]) = Ok s
  fromLispConfig c =
    Bad $ "Unable to extract a String from this configuration: "
      ++ show c

-- | Instance of FromLispConfig for [LispConfig]
instance FromLispConfig [LispConfig] where
  fromLispConfig (LCList l) = Ok l
  fromLispConfig c =
    Bad $ "Unable to extract a List from this configuration: "
      ++ show c

-- Data type representing the information that can be obtained from @xm uptime@
data UptimeInfo = UptimeInfo
  { uInfoName   :: String
  , uInfoID     :: Int
  , uInfoUptime :: String
  } deriving (Eq, Show)

data ActualState = ActualRunning  -- ^ The instance is running
                 | ActualBlocked  -- ^ The instance is not running or runnable
                 | ActualPaused   -- ^ The instance has been paused
                 | ActualShutdown -- ^ The instance is shut down
                 | ActualCrashed  -- ^ The instance has crashed
                 | ActualDying    -- ^ The instance is in process of dying
                 | ActualHung     -- ^ The instance is hung
                 | ActualUnknown  -- ^ Unknown state. Parsing error.
                 deriving (Show, Eq)

instance J.JSON ActualState where
  showJSON ActualRunning = J.showJSON "running"
  showJSON ActualBlocked = J.showJSON "blocked"
  showJSON ActualPaused = J.showJSON "paused"
  showJSON ActualShutdown = J.showJSON "shutdown"
  showJSON ActualCrashed = J.showJSON "crashed"
  showJSON ActualDying = J.showJSON "dying"
  showJSON ActualHung = J.showJSON "hung"
  showJSON ActualUnknown = J.showJSON "unknown"

  readJSON = error "JSON read instance not implemented for type ActualState"
