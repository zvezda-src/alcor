{-# LANGUAGE TemplateHaskell, BangPatterns #-}
{-| Types for the JQScheduler.

-}

{-
-}

module Alcor.JQScheduler.Types where

import System.INotify

import Alcor.JQueue as JQ
import Alcor.Lens hiding (chosen)
import Alcor.Utils

data JobWithStat = JobWithStat { jINotify :: Maybe INotify
                               , jStat :: FStat
                               , jJob :: !QueuedJob
                               } deriving (Eq, Show)

$(makeCustomLenses' ''JobWithStat ['jJob])


-- | A job without `INotify` and `FStat`.
nullJobWithStat :: QueuedJob -> JobWithStat
nullJobWithStat = JobWithStat Nothing nullFStat


data Queue = Queue { qEnqueued :: ![JobWithStat]
                   , qRunning :: ![JobWithStat]
                   , qManipulated :: ![JobWithStat] -- ^ running jobs that are
                                                   -- being manipulated by
                                                   -- some thread
                   } deriving (Eq, Show)

$(makeCustomLenses ''Queue)
