{-| Tag constants

This module holds all the special tag prefixes honored
by Alcor's htools. The module itself does not depend
on anything Alcor specific so that it can be imported
anywhere.

-}

{-
-}

module Alcor.HTools.Tags.Constants
  ( exTagsPrefix
  , standbyPrefix
  , migrationPrefix
  , allowMigrationPrefix
  , locationPrefix
  , desiredLocationPrefix
  , standbyAuto
  , autoRepairTagPrefix
  , autoRepairTagEnabled
  , autoRepairTagPending
  , autoRepairTagResult
  , autoRepairTagSuspended
  ) where

-- | The exclusion tag prefix. Instance tags starting with this prefix
-- describe a service provided by the instance. Instances providing the
-- same service at not places on the same node.
exTagsPrefix :: String
exTagsPrefix = "htools:iextags:"

-- | The tag-prefix indicating that hsqueeze should consider a node
-- as being standby.
standbyPrefix :: String
standbyPrefix = "htools:standby:"

-- | The prefix for migration tags
migrationPrefix :: String
migrationPrefix = "htools:migration:"

-- | Prefix of tags allowing migration
allowMigrationPrefix :: String
allowMigrationPrefix = "htools:allowmigration:"

-- | The prefix for node location tags.
locationPrefix :: String
locationPrefix = "htools:nlocation:"

-- | The prefix for instance desired location tags.
desiredLocationPrefix :: String
desiredLocationPrefix = "htools:desiredlocation:"

-- | The tag to be added to nodes that were shutdown by hsqueeze.
standbyAuto :: String
standbyAuto = "htools:standby:auto"

-- | Auto-repair tag prefix
autoRepairTagPrefix :: String
autoRepairTagPrefix = "alcor:watcher:autorepair:"

autoRepairTagEnabled :: String
autoRepairTagEnabled = autoRepairTagPrefix

autoRepairTagPending :: String
autoRepairTagPending = autoRepairTagPrefix ++ "pending:"

autoRepairTagResult :: String
autoRepairTagResult = autoRepairTagPrefix ++ "result:"

autoRepairTagSuspended :: String
autoRepairTagSuspended = autoRepairTagPrefix ++ "suspend:"

