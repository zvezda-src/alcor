{-# LANGUAGE TemplateHaskell #-}
{-| CPUload data types

This module holds the definition of the data types describing the CPU
load according to information collected periodically from @/proc/stat@.

-}
{-
-}
module Alcor.Cpu.Types
  ( CPUstat(..)
  , CPUavgload(..)
  ) where

import Alcor.THH

-- | This is the format of the report produced by the cpu load
-- collector.
$(buildObject "CPUavgload" "cav"
  [ simpleField "cpu_number" [t| Int |]
  , simpleField "cpus"       [t| [Double] |]
  , simpleField "cpu_total"  [t| Double |]
  ])

-- | This is the format of the data parsed by the input file.
$(buildObject "CPUstat" "cs"
  [ simpleField "name"       [t| String |]
  , simpleField "user"       [t| Int |]
  , simpleField "nice"       [t| Int |]
  , simpleField "system"     [t| Int |]
  , simpleField "idle"       [t| Int |]
  , simpleField "iowait"     [t| Int |]
  , simpleField "irq"        [t| Int |]
  , simpleField "softirq"    [t| Int |]
  , simpleField "steal"      [t| Int |]
  , simpleField "guest"      [t| Int |]
  , simpleField "guest_nice" [t| Int |]
  ])
