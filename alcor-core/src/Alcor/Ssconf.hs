{-# LANGUAGE TemplateHaskell #-}

{-| Implementation of the Alcor Ssconf interface.

-}

{-
-}

module Alcor.Ssconf
  ( SSKey(..)
  , sSKeyToRaw
  , sSKeyFromRaw
  , hvparamsSSKey
  , getPrimaryIPFamily
  , parseNodesVmCapable
  , getNodesVmCapable
  , getMasterCandidatesIps
  , getMasterNode
  , parseHypervisorList
  , getHypervisorList
  , parseEnabledUserShutdown
  , getEnabledUserShutdown
  , keyToFilename
  , sSFilePrefix
  , SSConf(..)
  , emptySSConf
  ) where

import Control.Arrow ((&&&))
import Control.Exception
import Control.Monad (forM, liftM)
import Control.Monad.Fail (MonadFail)
import qualified Data.Map as M
import Data.Maybe (fromMaybe)
import qualified Network.Socket as Socket
import System.FilePath ((</>))
import System.IO.Error (isDoesNotExistError)
import qualified Text.JSON as J

import qualified AutoConf
import Alcor.BasicTypes
import qualified Alcor.Constants as C
import qualified Alcor.ConstantUtils as CU
import Alcor.JSON (GenericContainer(..), HasStringRepr(..))
import qualified Alcor.Path as Path
import Alcor.THH
import Alcor.Types (Hypervisor)
import qualified Alcor.Types as Types
import Alcor.Utils

-- * Reading individual ssconf entries

-- | Maximum ssconf file size we support.
maxFileSize :: Int
maxFileSize = 131072

-- | ssconf file prefix, re-exported from Constants.
sSFilePrefix :: FilePath
sSFilePrefix = C.ssconfFileprefix

$(declareLADT ''String "SSKey" (
  map (ssconfConstructorName &&& id) . CU.toList $ C.validSsKeys
  ))

instance HasStringRepr SSKey where
  fromStringRepr = sSKeyFromRaw
  toStringRepr = sSKeyToRaw

-- | For a given hypervisor get the corresponding SSConf key that contains its
-- parameters.
--
-- The corresponding SSKeys are generated automatically by TH, but since we
-- don't have convenient infrastructure for generating this function, it's just
-- manual. All constructors must be given explicitly so that adding another
-- hypervisor will trigger "incomplete pattern" warning and force the
-- corresponding addition.
hvparamsSSKey :: Types.Hypervisor -> SSKey
hvparamsSSKey Types.Kvm = SSHvparamsKvm
hvparamsSSKey Types.XenPvm = SSHvparamsXenPvm
hvparamsSSKey Types.Chroot = SSHvparamsChroot
hvparamsSSKey Types.XenHvm = SSHvparamsXenHvm
hvparamsSSKey Types.Lxc = SSHvparamsLxc
hvparamsSSKey Types.Fake = SSHvparamsFake

-- | Convert a ssconf key into a (full) file path.
keyToFilename :: FilePath     -- ^ Config path root
              -> SSKey        -- ^ Ssconf key
              -> FilePath     -- ^ Full file name
keyToFilename cfgpath key =
  cfgpath </> sSFilePrefix ++ sSKeyToRaw key

-- | Runs an IO action while transforming any error into 'Bad'
-- values. It also accepts an optional value to use in case the error
-- is just does not exist.
catchIOErrors :: Maybe a         -- ^ Optional default
              -> IO a            -- ^ Action to run
              -> IO (Result a)
catchIOErrors def action =
  Control.Exception.catch
        (do
          result <- action
          return (Ok result)
        ) (\err -> let bad_result = Bad (show err)
                   in return $ if isDoesNotExistError err
                                 then maybe bad_result Ok def
                                 else bad_result)

-- | Read an ssconf file.
readSSConfFile :: Maybe FilePath            -- ^ Optional config path override
               -> Maybe String              -- ^ Optional default value
               -> SSKey                     -- ^ Desired ssconf key
               -> IO (Result String)
readSSConfFile optpath def key = do
  dpath <- Path.dataDir
  result <- catchIOErrors def . readFile .
            keyToFilename (fromMaybe dpath optpath) $ key
  return (liftM (take maxFileSize) result)

-- | Parses a key-value pair of the form "key=value" from 'str', fails
-- with 'desc' otherwise.
parseKeyValue :: MonadFail m => String -> String -> m (String, String)
parseKeyValue desc str =
  case sepSplit '=' str of
    [key, value] -> return (key, value)
    _ -> fail $ "Failed to parse key-value pair for " ++ desc

-- | Parses a string containing an IP family
parseIPFamily :: Int -> Result Socket.Family
parseIPFamily fam | fam == AutoConf.pyAfInet4 = Ok Socket.AF_INET
                  | fam == AutoConf.pyAfInet6 = Ok Socket.AF_INET6
                  | otherwise = Bad $ "Unknown af_family value: " ++ show fam

-- | Read the primary IP family.
getPrimaryIPFamily :: Maybe FilePath -> IO (Result Socket.Family)
getPrimaryIPFamily optpath = do
  result <- readSSConfFile optpath
                           (Just (show AutoConf.pyAfInet4))
                           SSPrimaryIpFamily
  return (liftM rStripSpace result >>=
          tryRead "Parsing af_family" >>= parseIPFamily)

-- | Parse the nodes vm capable value from a 'String'.
parseNodesVmCapable :: String -> Result [(String, Bool)]
parseNodesVmCapable str =
  forM (lines str) $ \line -> do
    (key, val) <- parseKeyValue "Parsing node_vm_capable" line
    val' <- tryRead "Parsing value of node_vm_capable" val
    return (key, val')

-- | Read and parse the nodes vm capable.
getNodesVmCapable :: Maybe FilePath -> IO (Result [(String, Bool)])
getNodesVmCapable optPath =
  (parseNodesVmCapable =<<) <$> readSSConfFile optPath Nothing SSNodeVmCapable

-- | Read the list of IP addresses of the master candidates of the cluster.
getMasterCandidatesIps :: Maybe FilePath -> IO (Result [String])
getMasterCandidatesIps optPath = do
  result <- readSSConfFile optPath Nothing SSMasterCandidatesIps
  return $ liftM lines result

-- | Read the name of the master node.
getMasterNode :: Maybe FilePath -> IO (Result String)
getMasterNode optPath = do
  result <- readSSConfFile optPath Nothing SSMasterNode
  return (liftM rStripSpace result)

-- | Parse the list of enabled hypervisors from a 'String'.
parseHypervisorList :: String -> Result [Hypervisor]
parseHypervisorList str =
  mapM Types.hypervisorFromRaw $ lines str

-- | Read and parse the list of enabled hypervisors.
getHypervisorList :: Maybe FilePath -> IO (Result [Hypervisor])
getHypervisorList optPath =
  (parseHypervisorList =<<) <$>
    readSSConfFile optPath Nothing SSHypervisorList

-- | Parse whether user shutdown is enabled from a 'String'.
parseEnabledUserShutdown :: String -> Result Bool
parseEnabledUserShutdown str =
  tryRead "Parsing enabled_user_shutdown" (rStripSpace str)

-- | Read and parse whether user shutdown is enabled.
getEnabledUserShutdown :: Maybe FilePath -> IO (Result Bool)
getEnabledUserShutdown optPath =
  (parseEnabledUserShutdown =<<) <$>
    readSSConfFile optPath Nothing SSEnabledUserShutdown

-- * Working with the whole ssconf map

-- | The data type used for representing the ssconf.
newtype SSConf = SSConf { getSSConf :: M.Map SSKey [String] }
  deriving (Eq, Ord, Show)

instance J.JSON SSConf where
  showJSON = J.showJSON . GenericContainer . getSSConf
  readJSON = liftM (SSConf . fromContainer) . J.readJSON

emptySSConf :: SSConf
emptySSConf = SSConf M.empty
