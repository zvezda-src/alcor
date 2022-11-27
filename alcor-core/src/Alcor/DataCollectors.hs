{-| Definition of the data collectors used by MonD.

-}

{-
-}

module Alcor.DataCollectors( collectors ) where

import qualified Data.ByteString.UTF8 as UTF8
import Data.Map (findWithDefault)

import qualified Alcor.DataCollectors.CPUload as CPUload
import qualified Alcor.DataCollectors.Diskstats as Diskstats
import qualified Alcor.DataCollectors.Drbd as Drbd
import qualified Alcor.DataCollectors.InstStatus as InstStatus
import qualified Alcor.DataCollectors.Lv as Lv
import qualified Alcor.DataCollectors.XenCpuLoad as XenCpuLoad
import Alcor.DataCollectors.Types (DataCollector(..),ReportBuilder(..))
import Alcor.JSON (GenericContainer(..))
import Alcor.Objects
import Alcor.Types

-- | The list of available builtin data collectors.
collectors :: [DataCollector]
collectors =
  [ cpuLoadCollector
  , xenCpuLoadCollector
  , diskStatsCollector
  , drdbCollector
  , instStatusCollector
  , lvCollector
  ]
  where
    f .&&. g = \x y -> f x y && g x y
    xenHypervisor = flip elem [XenPvm, XenHvm]
    xenCluster _ cfg =
      any xenHypervisor . clusterEnabledHypervisors $ configCluster cfg
    collectorConfig name cfg =
      let config = fromContainer . clusterDataCollectors $ configCluster cfg
      in  findWithDefault mempty (UTF8.fromString name) config
    updateInterval name cfg = dataCollectorInterval $ collectorConfig name cfg
    activeConfig name cfg = dataCollectorActive $ collectorConfig name cfg
    diskStatsCollector =
      DataCollector Diskstats.dcName Diskstats.dcCategory
        Diskstats.dcKind (StatelessR Diskstats.dcReport) Nothing activeConfig
        updateInterval
    drdbCollector =
      DataCollector Drbd.dcName Drbd.dcCategory Drbd.dcKind
        (StatelessR Drbd.dcReport) Nothing activeConfig updateInterval
    instStatusCollector =
      DataCollector InstStatus.dcName InstStatus.dcCategory
        InstStatus.dcKind (StatelessR InstStatus.dcReport) Nothing
        (xenCluster .&&. activeConfig)  updateInterval
    lvCollector =
      DataCollector Lv.dcName Lv.dcCategory Lv.dcKind
        (StatelessR Lv.dcReport) Nothing activeConfig updateInterval
    cpuLoadCollector =
      DataCollector CPUload.dcName CPUload.dcCategory CPUload.dcKind
        (StatefulR CPUload.dcReport) (Just CPUload.dcUpdate) activeConfig
        updateInterval
    xenCpuLoadCollector =
      DataCollector XenCpuLoad.dcName XenCpuLoad.dcCategory XenCpuLoad.dcKind
        (StatefulR XenCpuLoad.dcReport) (Just XenCpuLoad.dcUpdate) activeConfig
        updateInterval
