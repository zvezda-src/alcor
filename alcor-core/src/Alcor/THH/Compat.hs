{-# LANGUAGE CPP, TemplateHaskell #-}

{-| Shim library for supporting various Template Haskell versions

-}

{-
-}

module Alcor.THH.Compat
  ( gntInstanceD
  , gntDataD
  , extractDataDConstructors
  , myNotStrict
  , nonUnaryTupE
  ) where

import Language.Haskell.TH

-- | Convert Names to DerivClauses
--
-- template-haskell 2.12 (GHC 8.2) has changed the DataD class of
-- constructors to expect [DerivClause] instead of [Names]. Handle this in a
-- backwards-compatible way.
derivesFromNames :: [Name] -> [DerivClause]
derivesFromNames names = [DerivClause Nothing $ map ConT names]
derivesFromNames :: [Name] -> Cxt
derivesFromNames names = map ConT names

-- | DataD "constructor" function
--
-- Handle TH 2.11 and 2.12 changes in a transparent manner using the pre-2.11
-- API.
gntDataD :: Cxt -> Name -> [TyVarBndr] -> [Con] -> [Name] -> Dec
gntDataD x y z a b =
    DataD x y z Nothing a $ derivesFromNames b
    DataD x y z Nothing a $ map ConT b
    DataD x y z a b

-- | InstanceD "constructor" function
--
-- Handle TH 2.11 and 2.12 changes in a transparent manner using the pre-2.11
-- API.
gntInstanceD :: Cxt -> Type -> [Dec] -> Dec
gntInstanceD x y =
    InstanceD Nothing x y
    InstanceD x y

-- | Extract constructors from a DataD instance
--
-- Handle TH 2.11 changes by abstracting pattern matching against DataD.
extractDataDConstructors :: Info -> Maybe [Con]
extractDataDConstructors info =
    case info of
    TyConI (DataD _ _ _ Nothing cons _) -> Just cons
    TyConI (DataD _ _ _ cons _) -> Just cons
    _ -> Nothing

-- | Strict has been replaced by Bang, so redefine NotStrict in terms of the
-- latter.

myNotStrict :: Bang
myNotStrict = Bang NoSourceUnpackedness NoSourceStrictness
myNotStrict = NotStrict

-- | TupE changed from '[Exp] -> Exp' to '[Maybe Exp] -> Exp'.
-- Provide the old signature for compatibility.
nonUnaryTupE :: [Exp] -> Exp
nonUnaryTupE es = TupE $ map Just es
nonUnaryTupE es = TupE $ es
