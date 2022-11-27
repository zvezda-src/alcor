{-| Algorithm Options for HTools

This module describes the parameters that influence the balancing
algorithm in htools.

-}

{-
-}

module Alcor.HTools.AlgorithmParams
  ( AlgorithmOptions(..)
  , defaultOptions
  , fromCLIOptions
  ) where

import qualified Alcor.HTools.CLI as CLI
import qualified Alcor.HTools.Types as T

data AlgorithmOptions = AlgorithmOptions
  { algDiskMoves :: Bool            -- ^ Whether disk moves are allowed
  , algInstanceMoves :: Bool        -- ^ Whether instance moves are allowed
  , algRestrictedMigration :: Bool  -- ^ Whether migration is restricted
  , algIgnoreSoftErrors :: Bool     -- ^ Whether to always ignore soft errors
  , algEvacMode :: Bool             -- ^ Consider only eavacation moves
  , algMinGain :: Double            -- ^ Minimal gain per balancing step
  , algMinGainLimit :: Double       -- ^ Limit below which minimal gain is used
  , algCapacity :: Bool             -- ^ Whether to check capacity properties,
                                    -- like global N+1 redundancy
  , algCapacityIgnoreGroups :: [T.Gdx] -- ^ Groups to ignore in capacity checks
  , algRestrictToNodes :: Maybe [String] -- ^ nodes to restrict allocation to
  , algAcceptExisting :: Bool       -- ^ accept existing violations in capacity
                                    -- checks
  }

-- | Obtain the relevant algorithmic option from the commandline options
fromCLIOptions :: CLI.Options -> AlgorithmOptions
fromCLIOptions opts = AlgorithmOptions
  { algDiskMoves = CLI.optDiskMoves opts
  , algInstanceMoves = CLI.optInstMoves opts
  , algRestrictedMigration = CLI.optRestrictedMigrate opts
  , algIgnoreSoftErrors = CLI.optIgnoreSoftErrors opts
  , algEvacMode = CLI.optEvacMode opts
  , algMinGain = CLI.optMinGain opts
  , algMinGainLimit = CLI.optMinGainLim opts
  , algCapacity = CLI.optCapacity opts
  , algCapacityIgnoreGroups = []
  , algRestrictToNodes = CLI.optRestrictToNodes opts
  , algAcceptExisting = CLI.optAcceptExisting opts
  }

-- | Default options for the balancing algorithm
defaultOptions :: AlgorithmOptions
defaultOptions = fromCLIOptions CLI.defaultOptions
