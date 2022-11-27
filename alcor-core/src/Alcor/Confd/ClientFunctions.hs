{-| Some utility functions, based on the Confd client, providing data
 in a ready-to-use way.
-}

{-
-}

module Alcor.Confd.ClientFunctions
  ( getInstances
  , getInstanceDisks
  ) where

import Control.Monad (liftM)
import qualified Text.JSON as J

import Alcor.BasicTypes as BT
import Alcor.Confd.Types
import Alcor.Confd.Client
import Alcor.Objects


-- | Get the list of instances the given node is ([primary], [secondary]) for.
-- The server address and the server port parameters are mainly intended
-- for testing purposes. If they are Nothing, the default values will be used.
getInstances
  :: String
  -> Maybe String
  -> Maybe Int
  -> BT.ResultT String IO ([Alcor.Objects.Instance], [Alcor.Objects.Instance])
getInstances node srvAddr srvPort = do
  client <- liftIO $ getConfdClient srvAddr srvPort
  reply <- liftIO . query client ReqNodeInstances $ PlainQuery node
  case fmap (J.readJSON . confdReplyAnswer) reply of
    Just (J.Ok instances) -> return instances
    Just (J.Error msg) -> fail msg
    Nothing -> fail "No answer from the Confd server"

-- | Get the list of disks that belong to a given instance
-- The server address and the server port parameters are mainly intended
-- for testing purposes. If they are Nothing, the default values will be used.
getDisks
  :: Alcor.Objects.Instance
  -> Maybe String
  -> Maybe Int
  -> BT.ResultT String IO [Alcor.Objects.Disk]
getDisks inst srvAddr srvPort = do
  client <- liftIO $ getConfdClient srvAddr srvPort
  reply <- liftIO . query client ReqInstanceDisks . PlainQuery . uuidOf $ inst
  case fmap (J.readJSON . confdReplyAnswer) reply of
    Just (J.Ok disks) -> return disks
    Just (J.Error msg) -> fail msg
    Nothing -> fail "No answer from the Confd server"

-- | Get the list of instances on the given node along with their disks
-- The server address and the server port parameters are mainly intended
-- for testing purposes. If they are Nothing, the default values will be used.
getInstanceDisks
  :: String
  -> Maybe String
  -> Maybe Int
  -> BT.ResultT String IO [(Alcor.Objects.Instance, [Alcor.Objects.Disk])]
getInstanceDisks node srvAddr srvPort =
  liftM (uncurry (++)) (getInstances node srvAddr srvPort) >>=
    mapM (\i -> liftM ((,) i) (getDisks i srvAddr srvPort))
