{-# LANGUAGE TemplateHaskell, FunctionalDependencies, FlexibleContexts, CPP,
             GeneralizedNewtypeDeriving, TypeFamilies, UndecidableInstances #-}
-- {-# OPTIONS_GHC -fno-warn-warnings-deprecations #-}

{-| Creates a client out of list of RPC server components.

-}

{-
-}

module Alcor.THH.HsRPC
  ( RpcClientMonad
  , runRpcClient
  , mkRpcCall
  , mkRpcCalls
  ) where

import Control.Monad
import Control.Monad.Base
import Control.Monad.Error
import Control.Monad.Fail (MonadFail)
import Control.Monad.Reader
import Control.Monad.Trans.Control
import Language.Haskell.TH
import qualified Text.JSON as J

import Alcor.BasicTypes
import Alcor.Errors
import Alcor.JSON (fromJResultE)
import Alcor.THH.Types
import Alcor.UDSServer


-- * The monad for RPC clients

-- | The monad for all client RPC functions.
-- Given a client value, it runs the RPC call in IO and either retrieves the
-- result or the error.
newtype RpcClientMonad a =
  RpcClientMonad { runRpcClientMonad :: ReaderT Client ResultG a }
  deriving (Functor, Applicative, Monad, MonadFail, MonadIO, MonadBase IO,
            MonadError AlcorException)

instance MonadBaseControl IO RpcClientMonad where
-- Needs Undecidable instances
  type StM RpcClientMonad b = StM (ReaderT Client ResultG) b
  liftBaseWith f = RpcClientMonad $ liftBaseWith
                   $ \r -> f (r . runRpcClientMonad)
  restoreM = RpcClientMonad . restoreM
  newtype StM RpcClientMonad b = StMRpcClientMonad
    { runStMRpcClientMonad :: StM (ReaderT Client ResultG) b }
  liftBaseWith f = RpcClientMonad . liftBaseWith
                   $ \r -> f (liftM StMRpcClientMonad . r . runRpcClientMonad)
  restoreM = RpcClientMonad . restoreM . runStMRpcClientMonad

-- * The TH functions to construct RPC client functions from RPC server ones

-- | Given a client run a given client RPC action.
runRpcClient :: (MonadBase IO m, MonadError AlcorException m)
             => RpcClientMonad a -> Client -> m a
runRpcClient = (toErrorBase .) . runReaderT . runRpcClientMonad

callMethod :: (J.JSON r, J.JSON args) => String -> args -> RpcClientMonad r
callMethod method args = do
  client <- RpcClientMonad ask
  let request = buildCall method (J.showJSON args)
  liftIO $ sendMsg client request
  response <- liftIO $ recvMsg client
  toError $ parseResponse response
            >>= fromJResultE "Parsing RPC JSON response" . J.readJSON

-- | Given a server RPC function (such as from WConfd.Core), creates
-- the corresponding client function. The monad of the result type of the
-- given function is replaced by 'RpcClientMonad' and the new function
-- is implemented to issue a RPC call to the server.
mkRpcCall :: Name -> Q [Dec]
mkRpcCall name = do
  let bname = nameBase name
      fname = mkName bname  -- the name of the generated function
  (args, rtype) <- funArgs <$> typeOfFun name
  rarg <- argumentType rtype
  let ftype = foldr (\a t -> AppT (AppT ArrowT a) t)
                    (AppT (ConT ''RpcClientMonad) rarg) args
  body <- [| $(curryN $ length args) (callMethod $(stringE bname)) |]
  return [ SigD fname ftype
         , ValD (VarP fname) (NormalB body) []
         ]

-- Given a list of server RPC functions creates the corresponding client
-- RPC functions.
--
-- See 'mkRpcCall'
mkRpcCalls :: [Name] -> Q [Dec]
mkRpcCalls = liftM concat . mapM mkRpcCall
