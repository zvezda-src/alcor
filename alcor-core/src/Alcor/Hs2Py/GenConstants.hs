{-| Template Haskell code for Haskell to Python constants.

-}

{-
-}
{-# LANGUAGE TemplateHaskell #-}
module Alcor.Hs2Py.GenConstants (genPyConstants) where

import Language.Haskell.TH

import Alcor.THH

fileFromModule :: Maybe String -> String
fileFromModule Nothing = ""
fileFromModule (Just name) = "src/" ++ map dotToSlash name ++ ".hs"
  where dotToSlash '.' = '/'
        dotToSlash c = c

comment :: Name -> String
comment name =
  "# Generated automatically from Haskell constant '" ++ nameBase name ++
  "' in file '" ++ fileFromModule (nameModule name) ++ "'"

genList :: Name -> [Name] -> Q [Dec]
genList name consNames = do
  let cons = listE $ map (\n -> tupE [mkString n, mkPyValueEx n]) consNames
  sig <- sigD name [t| [(String, String)] |]
  fun <- funD name [clause [] (normalB cons) []]
  return [sig, fun]
  where mkString n = stringE (comment n ++ "\n" ++ deCamelCase (nameBase n))
        mkPyValueEx n = [| showValue $(varE n) |]

genPyConstants :: String -> [Name] -> Q [Dec]
genPyConstants name = genList (mkName name)
