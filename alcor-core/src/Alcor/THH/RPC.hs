{-# LANGUAGE TemplateHaskell, ExistentialQuantification #-}

{-| Implements Template Haskell generation of RPC server components from Haskell
functions.

-}

{-
-}

module Alcor.THH.RPC
  ( Request(..)
  , RpcServer
  , dispatch
  , mkRpcM
  ) where

import Control.Arrow ((&&&))
import Control.Monad
import Control.Monad.Error.Class
import Data.Map (Map)
import qualified Data.Map as Map
import Language.Haskell.TH
import qualified Text.JSON as J

import Alcor.BasicTypes
import Alcor.Errors
import Alcor.JSON (fromJResultE, fromJVal)
import Alcor.THH.Types
import qualified Alcor.UDSServer as US

data RpcFn m = forall i o . (J.JSON i, J.JSON o) => RpcFn (i -> m o)

type RpcServer m = US.Handler Request m J.JSValue

-- | A RPC request consiting of a method and its argument(s).
data Request = Request { rMethod :: String, rArgs :: J.JSValue }
  deriving (Eq, Ord, Show)

decodeRequest :: J.JSValue -> J.JSValue -> Result Request
decodeRequest method args = Request <$> fromJVal method <*> pure args


dispatch :: (Monad m)
         => Map String (RpcFn (ResultT AlcorException m)) -> RpcServer m
dispatch fs =
  US.Handler { US.hParse         = decodeRequest
             , US.hInputLogShort = rMethod
             , US.hInputLogLong  = rMethod
             , US.hExec          = liftToHandler . exec
             }
  where
    orError :: (MonadError e m, Error e) => Maybe a -> e -> m a
    orError m e = maybe (throwError e) return m

    exec (Request m as) = do
      (RpcFn f) <- orError (Map.lookup m fs)
                           (strMsg $ "No such method: " ++ m)
      i <- fromJResultE "RPC input" . J.readJSON $ as
      o <- f i -- lift $ f i
      return $ J.showJSON o

    liftToHandler :: (Monad m)
                  => ResultT AlcorException m J.JSValue
                  -> US.HandlerResult m J.JSValue
    liftToHandler = liftM ((,) True) . runResultT

-- | Converts a function into the appropriate @RpcFn m@ expression.
-- The function's result must be monadic.
toRpcFn :: Name -> Q Exp
toRpcFn name = [| RpcFn $( uncurryVar name ) |]

-- | Convert a list of named expressions into an expression containing a list
-- of name/expression pairs.
rpcFnsList :: [(String, Q Exp)] -> Q Exp
rpcFnsList = listE . map (\(name, expr) -> tupE [stringE name, expr])

-- | Takes a list of function names and creates a RPC handler that delegates
-- calls to them.
--
-- The functions must conform to
-- @(J.JSON i, J.JSON o) => i -> ResultT AlcorException m o@. The @m@
-- monads types of all the functions must unify.
--
-- The result expression is of type @RpcServer m@.
mkRpcM
    :: [Name]     -- ^ the names of functions to include
    -> Q Exp
mkRpcM names = [| dispatch . Map.fromList $
                        $( rpcFnsList . map (nameBase &&& toRpcFn) $ names ) |]
