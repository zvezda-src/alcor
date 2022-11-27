{-| Small module holding program definitions for data collectors.

-}

{-
-}

module Alcor.DataCollectors.Program (personalities) where

import Alcor.Common (PersonalityList)
import Alcor.DataCollectors.CLI (Options)

import qualified Alcor.DataCollectors.Diskstats as Diskstats
import qualified Alcor.DataCollectors.Drbd as Drbd
import qualified Alcor.DataCollectors.InstStatus as InstStatus
import qualified Alcor.DataCollectors.Lv as Lv

-- | Supported binaries.
personalities :: PersonalityList Options
personalities = [ (Drbd.dcName, (Drbd.main, Drbd.options, Drbd.arguments,
                                 "gathers and displays DRBD statistics in JSON\
                                 \ format"))
                , (InstStatus.dcName, (InstStatus.main, InstStatus.options,
                                       InstStatus.arguments,
                                       "gathers and displays the status of the\
                                       \ instances in JSON format"))
                , (Diskstats.dcName, (Diskstats.main, Diskstats.options,
                                      Diskstats.arguments,
                                      "gathers and displays the disk usage\
                                      \ statistics in JSON format"))
                , (Lv.dcName, (Lv.main, Lv.options, Lv.arguments, "gathers and\
                               \ displays info about logical volumes"))
                ]
