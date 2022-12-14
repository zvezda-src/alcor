{-| ConstantUtils contains the helper functions for constants

This module cannot be merged with 'Alcor.Utils' because it would
create a circular dependency if imported, for example, from
'Alcor.Constants'.

-}

{-
-}
module Alcor.ConstantUtils where

import Data.Char (ord)
import Data.Set (Set)
import qualified Data.Set as Set (difference, fromList, toList, union)
import qualified Data.Semigroup as Sem

import Alcor.PyValue

-- | 'PythonChar' wraps a Python 'char'
newtype PythonChar = PythonChar { unPythonChar :: Char }
  deriving (Show)

instance PyValue PythonChar where
  showValue c = "chr(" ++ show (ord (unPythonChar c)) ++ ")"

-- | 'PythonNone' wraps Python 'None'
data PythonNone = PythonNone

instance PyValue PythonNone where
  showValue _ = "None"

-- | FrozenSet wraps a Haskell 'Set'
--
-- See 'PyValue' instance for 'FrozenSet'.
newtype FrozenSet a = FrozenSet { unFrozenSet :: Set a }
  deriving (Eq, Ord, Show)

instance (Ord a) => Sem.Semigroup (FrozenSet a) where
  (FrozenSet s) <> (FrozenSet t) = FrozenSet (mappend s t)

instance (Ord a) => Monoid (FrozenSet a) where
  mempty = FrozenSet mempty
  mappend = (Sem.<>)

-- | Converts a Haskell 'Set' into a Python 'frozenset'
--
-- This instance was supposed to be for 'Set' instead of 'FrozenSet'.
-- However, 'ghc-6.12.1' seems to be crashing with 'segmentation
-- fault' due to the presence of more than one instance of 'Set',
-- namely, this one and the one in 'Alcor.OpCodes'.  For this reason,
-- we wrap 'Set' into 'FrozenSet'.
instance PyValue a => PyValue (FrozenSet a) where
  showValue s = "frozenset(" ++ showValue (Set.toList (unFrozenSet s)) ++ ")"

mkSet :: Ord a => [a] -> FrozenSet a
mkSet = FrozenSet . Set.fromList

toList :: FrozenSet a -> [a]
toList = Set.toList . unFrozenSet

union :: Ord a => FrozenSet a -> FrozenSet a -> FrozenSet a
union x y = FrozenSet (unFrozenSet x `Set.union` unFrozenSet y)

difference :: Ord a => FrozenSet a -> FrozenSet a -> FrozenSet a
difference x y = FrozenSet (unFrozenSet x `Set.difference` unFrozenSet y)

-- | 'Protocol' represents the protocols used by the daemons
data Protocol = Tcp | Udp
  deriving (Show)

-- | 'PyValue' instance of 'Protocol'
--
-- This instance is used by the Haskell to Python constants
instance PyValue Protocol where
  showValue Tcp = "\"tcp\""
  showValue Udp = "\"udp\""

-- | Failure exit code
--
-- These are defined here and not in 'Alcor.Constants' together with
-- the other exit codes in order to avoid a circular dependency
-- between 'Alcor.Constants' and 'Alcor.Runtime'
exitFailure :: Int
exitFailure = 1

-- | Console device
--
-- This is defined here and not in 'Alcor.Constants' order to avoid a
-- circular dependency between 'Alcor.Constants' and 'Alcor.Logging'
devConsole :: String
devConsole = "/dev/console"

-- | Random uuid generator
--
-- This is defined here and not in 'Alcor.Constants' order to avoid a
-- circular dependendy between 'Alcor.Constants' and 'Alcor.Types'
randomUuidFile :: String
randomUuidFile = "/proc/sys/kernel/random/uuid"

-- * Priority levels
--
-- This is defined here and not in 'Alcor.Types' in order to avoid a
-- GHC stage restriction and because there is no suitable 'declareADT'
-- variant that handles integer values directly.

priorityLow :: Int
priorityLow = 10

priorityNormal :: Int
priorityNormal = 0

priorityHigh :: Int
priorityHigh = -10

-- | Calculates int version number from major, minor and revision
-- numbers.
buildVersion :: Int -> Int -> Int -> Int
buildVersion major minor revision =
  1000000 * major + 10000 * minor + 1 * revision

-- | Confd protocol version
--
-- This is defined here in order to avoid a circular dependency
-- between 'Alcor.Confd.Types' and 'Alcor.Constants'.
confdProtocolVersion :: Int
confdProtocolVersion = 1

-- * Confd request query fields
--
-- These are defined here and not in 'Alcor.Types' due to GHC stage
-- restrictions concerning Template Haskell.  They are also not
-- defined in 'Alcor.Constants' in order to avoid a circular
-- dependency between that module and 'Alcor.Types'.

confdReqqLink :: String
confdReqqLink = "0"

confdReqqIp :: String
confdReqqIp = "1"

confdReqqIplist :: String
confdReqqIplist = "2"

confdReqqFields :: String
confdReqqFields = "3"

-- * ISpec

ispecMemSize :: String
ispecMemSize = "memory-size"

ispecCpuCount :: String
ispecCpuCount = "cpu-count"

ispecDiskCount :: String
ispecDiskCount = "disk-count"

ispecDiskSize :: String
ispecDiskSize = "disk-size"

ispecNicCount :: String
ispecNicCount = "nic-count"

ispecSpindleUse :: String
ispecSpindleUse = "spindle-use"

ispecsMinmax :: String
ispecsMinmax = "minmax"

ispecsStd :: String
ispecsStd = "std"

ipolicyDts :: String
ipolicyDts = "disk-templates"

ipolicyVcpuRatio :: String
ipolicyVcpuRatio = "vcpu-ratio"

ipolicySpindleRatio :: String
ipolicySpindleRatio = "spindle-ratio"

ipolicyDefaultsVcpuRatio :: Double
ipolicyDefaultsVcpuRatio = 4.0

ipolicyDefaultsSpindleRatio :: Double
ipolicyDefaultsSpindleRatio = 32.0
