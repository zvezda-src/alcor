{-# LANGUAGE TupleSections, TemplateHaskell, CPP, UndecidableInstances,
    MultiParamTypeClasses, TypeFamilies, GeneralizedNewtypeDeriving,
    ImpredicativeTypes #-}
{-| Functions of the metadata daemon exported for RPC

-}

{-
-}
module Alcor.Metad.ConfigCore where

import Control.Concurrent.MVar.Lifted
import Control.Monad.Base
import Control.Monad.IO.Class
import Control.Monad.Reader
import Control.Monad.Trans.Control
import Language.Haskell.TH (Name)
import qualified Text.JSON as J

import Alcor.BasicTypes
import Alcor.Errors
import qualified Alcor.JSON as J
import Alcor.Logging as L
import Alcor.Metad.Config as Config
import Alcor.Metad.Types (InstanceParams)

-- * The monad in which all the Metad functions execute

data MetadHandle = MetadHandle
  { mhInstParams :: MVar InstanceParams
  }

-- | A type alias for easier referring to the actual content of the monad
-- when implementing its instances.
type MetadMonadIntType = ReaderT MetadHandle IO

-- | The internal part of the monad without error handling.
newtype MetadMonadInt a = MetadMonadInt
  { getMetadMonadInt :: MetadMonadIntType a }
  deriving ( Functor, Applicative, Monad, MonadIO, MonadBase IO
           , L.MonadLog )

instance MonadBaseControl IO MetadMonadInt where
-- Needs Undecidable instances
  type StM MetadMonadInt b = StM MetadMonadIntType b
  liftBaseWith f = MetadMonadInt $ liftBaseWith
                   $ \r -> f (r . getMetadMonadInt)
  restoreM = MetadMonadInt . restoreM
  newtype StM MetadMonadInt b = StMMetadMonadInt
    { runStMMetadMonadInt :: StM MetadMonadIntType b }
  liftBaseWith f = MetadMonadInt . liftBaseWith
                   $ \r -> f (liftM StMMetadMonadInt . r . getMetadMonadInt)
  restoreM = MetadMonadInt . restoreM . runStMMetadMonadInt

-- | Runs the internal part of the MetadMonad monad on a given daemon
-- handle.
runMetadMonadInt :: MetadMonadInt a -> MetadHandle -> IO a
runMetadMonadInt (MetadMonadInt k) = runReaderT k

-- | The complete monad with error handling.
type MetadMonad = ResultT AlcorException MetadMonadInt

-- * Basic functions in the monad

metadHandle :: MetadMonad MetadHandle
metadHandle = lift . MetadMonadInt $ ask

instParams :: MetadMonad InstanceParams
instParams = readMVar . mhInstParams =<< metadHandle

modifyInstParams :: (InstanceParams -> MetadMonad (InstanceParams, a))
                 -> MetadMonad a
modifyInstParams f = do
  h <- metadHandle
  modifyMVar (mhInstParams h) f

-- * Functions available to the RPC module

-- Just a debugging function
echo :: String -> MetadMonad String
echo = return

-- | Update the configuration with the received instance parameters.
updateConfig :: J.JSValue -> MetadMonad ()
updateConfig input = do
  (name, m'instanceParams) <- J.fromJResultE "Could not get instance parameters"
                              $ Config.getInstanceParams input
  case m'instanceParams of
    Nothing -> L.logInfo $ "No communication NIC for instance " ++ name
                           ++ ", skipping"
    Just instanceParams -> do
      cfg' <- modifyInstParams $ \cfg ->
        let cfg' = mergeConfig cfg instanceParams
         in return (cfg', cfg')
      L.logInfo $
        "Updated instance " ++ name ++ " configuration"
      L.logDebug $ "Instance configuration: " ++ show cfg'

-- * The list of all functions exported to RPC.

exportedFunctions :: [Name]
exportedFunctions = [ 'echo
                    , 'updateConfig
                    ]
