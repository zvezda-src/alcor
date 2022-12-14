{-| Implementation of the Alcor Query2 node group queries.

 -}

{-
-}

module Alcor.Query.Network
  ( getGroupConnection
  , getNetworkUuid
  , instIsConnected
  , fieldsMap
  ) where

-- FIXME: everything except fieldsMap
-- is only exported for testing.

import qualified Data.ByteString.UTF8 as UTF8
import qualified Data.Map as Map
import Data.Maybe (fromMaybe, mapMaybe)
import Data.List (find, intercalate)

import Alcor.JSON (fromContainer)
import Alcor.Network
import Alcor.Objects
import qualified Alcor.Objects.BitArray as BA
import Alcor.Query.Language
import Alcor.Query.Common
import Alcor.Query.Types
import Alcor.Types

networkFields :: FieldList Network NoDataRuntime
networkFields =
  [ (FieldDefinition "name" "Network" QFTText "Name",
     FieldSimple (rsNormal . networkName), QffNormal)
  , (FieldDefinition "network" "Subnet" QFTText "IPv4 subnet",
     FieldSimple (rsNormal . networkNetwork), QffNormal)
  , (FieldDefinition "gateway" "Gateway" QFTOther "IPv4 gateway",
     FieldSimple (rsMaybeUnavail . networkGateway), QffNormal)
  , (FieldDefinition "network6" "IPv6Subnet" QFTOther "IPv6 subnet",
     FieldSimple (rsMaybeUnavail . networkNetwork6), QffNormal)
  , (FieldDefinition "gateway6" "IPv6Gateway" QFTOther "IPv6 gateway",
     FieldSimple (rsMaybeUnavail . networkGateway6), QffNormal)
  , (FieldDefinition "mac_prefix" "MacPrefix" QFTOther "MAC address prefix",
     FieldSimple (rsMaybeUnavail . networkMacPrefix), QffNormal)
  , (FieldDefinition "free_count" "FreeCount" QFTNumber "Number of available\
                                                       \ addresses",
     FieldSimple (rsNormal . getFreeCount),
     QffNormal)
  , (FieldDefinition "map" "Map" QFTText "Actual mapping",
     FieldSimple (rsNormal . getMap),
     QffNormal)
  , (FieldDefinition "reserved_count" "ReservedCount" QFTNumber
       "Number of reserved addresses",
     FieldSimple (rsNormal . getReservedCount),
     QffNormal)
  , (FieldDefinition "group_list" "GroupList" QFTOther
       "List of nodegroups (group name, NIC mode, NIC link)",
     FieldConfig (\cfg -> rsNormal . getGroupConnections cfg . uuidOf),
     QffNormal)
  , (FieldDefinition "group_cnt" "NodeGroups" QFTNumber "Number of nodegroups",
     FieldConfig (\cfg -> rsNormal . length . getGroupConnections cfg
       . uuidOf), QffNormal)
  , (FieldDefinition "inst_list" "InstanceList" QFTOther "List of instances",
     FieldConfig (\cfg -> rsNormal . getInstances cfg . uuidOf),
     QffNormal)
  , (FieldDefinition "inst_cnt" "Instances" QFTNumber "Number of instances",
     FieldConfig (\cfg -> rsNormal . length . getInstances cfg
       . uuidOf), QffNormal)
  , (FieldDefinition "external_reservations" "ExternalReservations" QFTText
     "External reservations",
     FieldSimple getExtReservationsString, QffNormal)
  ] ++
  timeStampFields ++
  uuidFields "Network" ++
  serialFields "Network" ++
  tagsFields

-- | The group fields map.
fieldsMap :: FieldMap Network NoDataRuntime
fieldsMap = fieldListToFieldMap networkFields

-- TODO: the following fields are not implemented yet: external_reservations

-- | Given a network's UUID, this function lists all connections from
-- the network to nodegroups including the respective mode and links.
getGroupConnections ::
  ConfigData -> String -> [(String, String, String, String)]
getGroupConnections cfg network_uuid =
  mapMaybe (getGroupConnection network_uuid)
  ((Map.elems . fromContainer . configNodegroups) cfg)

-- | Given a network's UUID and a node group, this function assembles
-- a tuple of the group's name, the mode and the link by which the
-- network is connected to the group. Returns 'Nothing' if the network
-- is not connected to the group.
getGroupConnection ::
  String -> NodeGroup -> Maybe (String, String, String, String)
getGroupConnection network_uuid group =
  let networks = fromContainer . groupNetworks $ group
  in case Map.lookup (UTF8.fromString network_uuid) networks of
    Nothing -> Nothing
    Just net ->
      Just (groupName group, getNicMode net, getNicLink net, getNicVlan net)

-- | Retrieves the network's mode and formats it human-readable,
-- also in case it is not available.
getNicMode :: PartialNicParams -> String
getNicMode nic_params =
  maybe "-" nICModeToRaw $ nicpModeP nic_params

-- | Retrieves the network's vlan and formats it human-readable, also in
-- case it it not available.
getNicLink :: PartialNicParams -> String
getNicLink nic_params = fromMaybe "-" (nicpLinkP nic_params)

-- | Retrieves the network's link and formats it human-readable, also in
-- case it it not available.
getNicVlan :: PartialNicParams -> String
getNicVlan nic_params = fromMaybe "-" (nicpVlanP nic_params)

-- | Retrieves the network's instances' names.
getInstances :: ConfigData -> String -> [String]
getInstances cfg network_uuid =
  mapMaybe instName (filter (instIsConnected network_uuid)
    ((Map.elems . fromContainer . configInstances) cfg))

-- | Helper function that checks if an instance is linked to the given network.
instIsConnected :: String -> Instance -> Bool
instIsConnected network_uuid inst =
  network_uuid `elem` mapMaybe nicNetwork (instNics inst)

-- | Helper function to look up a network's UUID by its name
getNetworkUuid :: ConfigData -> String -> Maybe String
getNetworkUuid cfg name =
  let net = find (\n -> name == fromNonEmpty (networkName n))
               ((Map.elems . fromContainer . configNetworks) cfg)
  in fmap uuidOf net

-- | Computes the reservations list for a network.
--
-- This doesn't use the netmask for validation of the length, instead
-- simply iterating over the reservations.
getReservations :: Ip4Network -> Maybe AddressPool -> [Ip4Address]
getReservations _ Nothing = []
getReservations net (Just pool) =
  map snd . filter fst
  $ zip (BA.toList . apReservations $ pool)
        (iterate nextIp4Address $ ip4BaseAddr net)

-- | Computes the external reservations as string for a network.
getExtReservationsString :: Network -> ResultEntry
getExtReservationsString net =
  let addrs = getReservations (networkNetwork net)
                              (networkExtReservations net)
  in rsNormal . intercalate ", " $ map show addrs
