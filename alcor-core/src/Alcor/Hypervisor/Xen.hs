{-| Module to access the information provided by the Xen hypervisor.

-}
{-
-}
module Alcor.Hypervisor.Xen
  ( getDomainsInfo
  , getInferredDomInfo
  , getUptimeInfo
  --Data types to be re-exported from here
  , Domain(..)
  , UptimeInfo(..)
  ) where

import qualified Control.Exception as E
import Data.Attoparsec.Text as A
import qualified Data.Map as Map
import Data.Text (pack)
import System.Process

import qualified Alcor.BasicTypes as BT
import qualified Alcor.Constants as C
import Alcor.Hypervisor.Xen.Types
import Alcor.Hypervisor.Xen.XlParser
import Alcor.Logging
import Alcor.Utils


-- | Get information about the current Xen domains as a map where the domain
-- name is the key. This only includes the information made available by Xen
-- itself.
getDomainsInfo :: IO (BT.Result (Map.Map String Domain))
getDomainsInfo = do
  contents <-
        (E.try $ readProcess "xl" ["list", "--long"] "")
          :: IO (Either IOError String)
  return $
    either (BT.Bad . show) (
      \c ->
        case A.parseOnly xlListParser $ pack c of
          Left msg -> BT.Bad msg
          Right dom -> BT.Ok dom
      ) contents

-- | Given a domain and a map containing information about multiple domains,
-- infer additional information about that domain (specifically, whether it is
-- hung).
inferDomInfos :: Map.Map String Domain -> Domain -> Domain
inferDomInfos domMap dom1 =
  case Map.lookup (domName dom1) domMap of
    Just dom2 ->
      dom1 { domIsHung = Just $ domCpuTime dom1 == domCpuTime dom2 }
    Nothing -> dom1 { domIsHung = Nothing }

-- | Get information about the current Xen domains as a map where the domain
-- name is the key. This includes information made available by Xen itself as
-- well as further information that can be inferred by querying Xen multiple
-- times and comparing the results.
getInferredDomInfo :: IO (BT.Result (Map.Map String Domain))
getInferredDomInfo = do
  domMap1 <- getDomainsInfo
  domMap2 <- getDomainsInfo
  case (domMap1, domMap2) of
    (BT.Bad m1, BT.Bad m2) -> return . BT.Bad $ m1 ++ "\n" ++ m2
    (BT.Bad m, BT.Ok d) -> do
      logWarning $ "Unable to retrieve domains info the first time" ++ m
      return $ BT.Ok d
    (BT.Ok d, BT.Bad m) -> do
      logWarning $ "Unable to retrieve domains info the second time" ++ m
      return $ BT.Ok d
    (BT.Ok d1, BT.Ok d2) -> return . BT.Ok $ fmap (inferDomInfos d2) d1

-- | Get information about the uptime of domains, as a map where the domain ID
-- is the key.
getUptimeInfo :: IO (Map.Map Int UptimeInfo)
getUptimeInfo = do
  contents <-
    ((E.try $ readProcess "xl" ["uptime"] "")
      :: IO (Either IOError String)) >>=
      exitIfBad "running command" . either (BT.Bad . show) BT.Ok
  case A.parseOnly xlUptimeParser $ pack contents of
    Left msg -> exitErr msg
    Right uInfo -> return uInfo
