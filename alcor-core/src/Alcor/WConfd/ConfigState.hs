{-# LANGUAGE TemplateHaskell #-}

{-| Pure functions for manipulating the configuration state.

-}

{-
-}

module Alcor.WConfd.ConfigState
  ( ConfigState
  , csConfigData
  , csConfigDataL
  , mkConfigState
  , bumpSerial
  , needsFullDist
  ) where

import Data.Function (on)
import System.Time (ClockTime(..))

import Alcor.Config
import Alcor.Lens
import Alcor.Objects
import Alcor.Objects.Lens

-- | In future this data type will include the current configuration
-- ('ConfigData') and the last 'FStat' of its file.
data ConfigState = ConfigState
  { csConfigData :: ConfigData
  }
  deriving (Eq, Show)

$(makeCustomLenses ''ConfigState)

-- | Creates a new configuration state.
-- This method will expand as more fields are added to 'ConfigState'.
mkConfigState :: ConfigData -> ConfigState
mkConfigState = ConfigState

bumpSerial :: (SerialNoObjectL a, TimeStampObjectL a) => ClockTime -> a -> a
bumpSerial now = set mTimeL now . over serialL succ

-- | Given two versions of the configuration, determine if its distribution
-- needs to be fully committed before returning the corresponding call to
-- WConfD.
needsFullDist :: ConfigState -> ConfigState -> Bool
needsFullDist = on (/=) (watched . csConfigData)
  where
    watched = (,,,,,,)
              <$> clusterCandidateCerts . configCluster
              <*> clusterMasterNode . configCluster
              <*> getMasterNodes
              <*> getMasterCandidates
              -- kvmd is running depending on the following:
              <*> clusterEnabledUserShutdown . configCluster
              <*> clusterEnabledHypervisors . configCluster
              <*> fmap nodeVmCapable . configNodes
