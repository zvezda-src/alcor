{-| Module describing an NIC.

The NIC data type only holds data about a NIC, but does not provide any
logic.

-}

{-
-}

module Alcor.HTools.Nic
  ( Nic(..)
  , Mode(..)
  , List
  , create
  ) where

import qualified Alcor.HTools.Container as Container

import qualified Alcor.HTools.Types as T

-- * Type declarations

data Mode = Bridged | Routed | OpenVSwitch deriving (Show, Eq)

-- | The NIC type.
--
-- It holds the data for a NIC as it is provided via the IAllocator protocol
-- for an instance creation request. All data in those request is optional,
-- that's why all fields are Maybe's.
--
-- TODO: Another name might be more appropriate for this type, as for example
-- RequestedNic. But this type is used as a field in the Instance type, which
-- is not named RequestedInstance, so such a name would be weird. PartialNic
-- already exists in Objects, but doesn't fit the bill here, as it contains
-- a required field (mac). Objects and the types therein are subject to being
-- reworked, so until then this type is left as is.
data Nic = Nic
  { mac          :: Maybe String -- ^ MAC address of the NIC
  , ip           :: Maybe String -- ^ IP address of the NIC
  , mode         :: Maybe Mode   -- ^ the mode the NIC operates in
  , link         :: Maybe String -- ^ the link of the NIC
  , bridge       :: Maybe String -- ^ the bridge this NIC is connected to if
                                 --   the mode is Bridged
  , network      :: Maybe T.NetworkID -- ^ network UUID if this NIC is connected
                                 --   to a network
  } deriving (Show, Eq)

-- | A simple name for an instance map.
type List = Container.Container Nic

-- * Initialization

-- | Create a NIC.
--
create :: Maybe String
       -> Maybe String
       -> Maybe Mode
       -> Maybe String
       -> Maybe String
       -> Maybe T.NetworkID
       -> Nic
create mac_init ip_init mode_init link_init bridge_init network_init =
  Nic { mac = mac_init
      , ip = ip_init
      , mode = mode_init
      , link = link_init
      , bridge = bridge_init
      , network = network_init
      }
