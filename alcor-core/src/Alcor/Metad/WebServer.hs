{-# LANGUAGE FlexibleContexts, OverloadedStrings #-}
{-| Web server for the metadata daemon.

-}

{-
-}

module Alcor.Metad.WebServer (start) where

import Control.Applicative
import Control.Concurrent (MVar, readMVar)
import Control.Monad.Base (MonadBase)
import Control.Monad.IO.Class (liftIO)
import Control.Exception.Lifted (catch, throwIO)
import Control.Exception.Base (Exception)
import Data.Typeable (Typeable)
import qualified Data.CaseInsensitive as CI
import Data.List (intercalate)
import Data.Map (Map)
import qualified Data.Map as Map
import qualified Data.ByteString.Char8 as ByteString (pack, unpack)
import Snap.Core
import Snap.Util.FileServe
import Snap.Http.Server
import Text.JSON (JSValue, Result(..), JSObject)
import qualified Text.JSON as JSON
import System.FilePath ((</>))

import Alcor.Daemon
import qualified Alcor.Constants as Constants
import qualified Alcor.Logging as Logging
import Alcor.Runtime (AlcorDaemon(..), ExtraLogReason(..))
import qualified Alcor.Runtime as Runtime

import Alcor.Metad.Config as Config
import Alcor.Metad.Types (InstanceParams)

type MetaM = Snap ()

data MetaMExc = MetaMExc String deriving (Show, Typeable)
instance Exception MetaMExc

throwError :: MonadBase IO m => String -> m a
throwError = throwIO . MetaMExc

split :: String -> [String]
split str =
  case span (/= '/') str of
    (x, []) -> [x]
    (x, _:xs) -> x:split xs

lookupInstanceParams :: MonadBase IO m => String -> Map String b -> m b
lookupInstanceParams inst params =
  case Map.lookup inst params of
    Nothing -> throwError $ "Could not get instance params for " ++ show inst
    Just x -> return x

-- | The 404 "not found" error.
error404 :: MetaM
error404 = do
  modifyResponse $ setResponseStatus 404 "Not found"
  writeBS "Resource not found"

-- | The 405 "method not allowed error", including the list of allowed methods.
error405 :: [Method] -> MetaM
error405 ms = modifyResponse $
  addHeader (CI.mk "Allow") (ByteString.pack . intercalate ", " $ map show ms)
  . setResponseStatus 405 "Method not allowed"

maybeResult :: MonadBase IO m => Result t -> (t -> m a) -> m a
maybeResult (Error err) _ = throwError err
maybeResult (Ok x) f = f x

serveOsParams :: String -> Map String JSValue -> MetaM
serveOsParams inst params =
  do instParams <- lookupInstanceParams inst params
     maybeResult (Config.getOsParamsWithVisibility instParams) $ \osParams ->
       writeBS .
       ByteString.pack .
       JSON.encode $ osParams

serveOsPackage :: String -> Map String JSValue -> String -> MetaM
serveOsPackage inst params key =
  do instParams <- lookupInstanceParams inst params
     maybeResult (JSON.readJSON instParams >>=
                  Config.getPublicOsParams >>=
                  getOsPackage) $ \package ->
       serveFile package `catch` \err ->
         throwError $ "Could not serve OS package: " ++ show (err :: IOError)
  where getOsPackage osParams =
          case lookup key (JSON.fromJSObject osParams) of
            Nothing -> Error $ "Could not find OS package for " ++ show inst
            Just x -> JSON.readJSON x

serveOsScript :: String -> Map String JSValue -> String -> MetaM
serveOsScript inst params script =
  do instParams <- lookupInstanceParams inst params
     maybeResult (getOsType instParams) $ \os ->
       if null os
       then throwError $ "There is no OS for " ++ show inst
       else serveScript os Constants.osSearchPath
  where getOsType instParams =
          do obj <- JSON.readJSON instParams :: Result (JSObject JSValue)
             case lookup "os" (JSON.fromJSObject obj) of
               Nothing -> Error $ "Could not find OS for " ++ show inst
               Just x -> JSON.readJSON x :: Result String

        serveScript :: String -> [String] -> MetaM
        serveScript os [] =
          throwError $ "Could not find OS script " ++ show (os </> script)
        serveScript os (d:ds) =
          serveFile (d </> os </> script)
          `catch`
          \err -> do let _ = err :: IOError
                     serveScript os ds

handleMetadata
  :: MVar InstanceParams -> Method -> String -> String -> String -> MetaM
handleMetadata _ GET  "alcor" "latest" "meta_data.json" =
  liftIO $ Logging.logInfo "alcor metadata"
handleMetadata params GET  "alcor" "latest" "os/os-install-package" =
  do remoteAddr <- ByteString.unpack . rqRemoteAddr <$> getRequest
     instanceParams <- liftIO $ do
       Logging.logInfo $ "OS install package for " ++ show remoteAddr
       readMVar params
     serveOsPackage remoteAddr instanceParams "os-install-package"
       `catch`
       \err -> do
         let MetaMExc e = err
         liftIO .
           Logging.logWarning $ "Could not serve OS install package: " ++ e
         error404
handleMetadata params GET  "alcor" "latest" "os/package" =
  do remoteAddr <- ByteString.unpack . rqRemoteAddr <$> getRequest
     instanceParams <- liftIO $ do
       Logging.logInfo $ "OS package for " ++ show remoteAddr
       readMVar params
     serveOsPackage remoteAddr instanceParams "os-package"
handleMetadata params GET  "alcor" "latest" "os/parameters.json" =
  do remoteAddr <- ByteString.unpack . rqRemoteAddr <$> getRequest
     instanceParams <- liftIO $ do
       Logging.logInfo $ "OS parameters for " ++ show remoteAddr
       readMVar params
     serveOsParams remoteAddr instanceParams `catch`
       \err -> do
         let MetaMExc e = err
         liftIO . Logging.logWarning $ "Could not serve OS parameters: " ++ e
         error404
handleMetadata params GET  "alcor" "latest" script | isScript script =
  do remoteAddr <- ByteString.unpack . rqRemoteAddr <$> getRequest
     instanceParams <- liftIO $ do
       Logging.logInfo $ "OS package for " ++ show remoteAddr
       readMVar params
     serveOsScript remoteAddr instanceParams (last $ split script) `catch`
       \err -> do
         let MetaMExc e = err
         liftIO . Logging.logWarning $ "Could not serve OS scripts: " ++ e
         error404
  where isScript =
          (`elem` [ "os/scripts/create"
                  , "os/scripts/export"
                  , "os/scripts/import"
                  , "os/scripts/rename"
                  , "os/scripts/verify"
                  ])
handleMetadata _ GET  "alcor" "latest" "read" =
  liftIO $ Logging.logInfo "alcor READ"
handleMetadata _ _  "alcor" "latest" "read" =
  error405 [GET]
handleMetadata _ POST "alcor" "latest" "write" =
  liftIO $ Logging.logInfo "alcor WRITE"
handleMetadata _ _ "alcor" "latest" "write" =
  error405 [POST]
handleMetadata _ _ _ _ _ =
  error404

routeMetadata :: MVar InstanceParams -> MetaM
routeMetadata params =
  route [ (providerRoute1, dispatchMetadata)
        , (providerRoute2, dispatchMetadata)
        ] <|> dispatchMetadata
  where provider = "provider"
        version  = "version"

        providerRoute1 = ByteString.pack $ ':':provider ++ "/" ++ ':':version
        providerRoute2 = ByteString.pack $ ':':version

        getParamString :: String -> Snap String
        getParamString =
          fmap (maybe "" ByteString.unpack) . getParam . ByteString.pack

        dispatchMetadata =
          do m <- rqMethod <$> getRequest
             p <- getParamString provider
             v <- getParamString version
             r <- ByteString.unpack . rqPathInfo <$> getRequest
             handleMetadata params m p v r

defaultHttpConf :: DaemonOptions -> FilePath -> FilePath -> Config Snap ()
defaultHttpConf opts accessLog errorLog =
  maybe id (setBind . ByteString.pack) (optBindAddress opts) .
  setAccessLog (ConfigFileLog accessLog) .
  setCompression False .
  setErrorLog (ConfigFileLog errorLog) .
  setPort (maybe Constants.defaultMetadPort fromIntegral (optPort opts)) .
  setVerbose False $
  emptyConfig

start :: DaemonOptions -> MVar InstanceParams -> IO ()
start opts params = do
  accessLog <- Runtime.daemonsExtraLogFile AlcorMetad AccessLog
  errorLog <- Runtime.daemonsExtraLogFile AlcorMetad ErrorLog
  httpServe (defaultHttpConf opts accessLog errorLog) (routeMetadata params)
