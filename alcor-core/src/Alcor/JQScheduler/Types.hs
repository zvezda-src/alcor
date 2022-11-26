{-# LANGUAGE TemplateHaskell, BangPatterns #-}
{-| Types for the JQScheduler.

-}

{-

Copyright (C) 2013 Google Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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