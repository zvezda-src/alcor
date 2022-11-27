{-# LANGUAGE TemplateHaskell #-}
{-| Type declarations specific for the instance status data collector.

-}

{-
-}

module Alcor.DataCollectors.InstStatusTypes
  ( InstStatus(..)
  , ReportData(..)
  ) where


import Alcor.DataCollectors.Types
import Alcor.Hypervisor.Xen.Types
import Alcor.THH
import Alcor.THH.Field
import Alcor.Types

-- | Data type representing the status of an instance to be returned.
$(buildObject "InstStatus" "iStat"
  [ simpleField "name"         [t| String |]
  , simpleField "uuid"         [t| String |]
  , simpleField "adminState"   [t| AdminState |]
  , simpleField "actualState"  [t| ActualState |]
  , optionalNullSerField $
    simpleField "uptime"       [t| String |]
  , timeAsDoubleField "mtime"
  , simpleField "state_reason" [t| ReasonTrail |]
  , simpleField "status"       [t| DCStatus |]
  ])

$(buildObject "ReportData" "rData"
  [ simpleField "instances" [t| [InstStatus] |]
  , simpleField "status"    [t| DCStatus |]
  ])
