{-| GenOpCodes handles Python opcode generation.

GenOpCodes contains the helper functions that generate the Python
opcodes as strings from the Haskell opcode description.

-}

{-
-}

module Alcor.Hs2Py.GenOpCodes (showPyClasses) where

import Data.List (intercalate)

import Alcor.OpCodes
import Alcor.THH

-- | Generates the Python class docstring.
pyClassDoc :: String -> String
pyClassDoc doc
  | length (lines doc) > 1 =
    "  \"\"\"" ++ doc ++ "\n\n" ++ "  \"\"\"" ++ "\n"
  | otherwise =
    "  \"\"\"" ++ doc ++ "\"\"\"" ++ "\n"

-- | Generates an opcode parameter in Python.
pyClassField :: OpCodeField -> String
pyClassField (OpCodeField name typ Nothing doc) =
  "(" ++ intercalate ", " [show name, "None", showValue typ, show doc] ++ ")"
pyClassField (OpCodeField name typ (Just def) doc) =
  "(" ++ intercalate ", "
           [show name, showValue def, showValue typ, show doc] ++ ")"

-- | Comma intercalates and indents opcode parameters in Python.
intercalateIndent :: [String] -> String
intercalateIndent xs = intercalate "," (map ("\n    " ++) xs)

-- | Generates an opcode as a Python class.
showPyClass :: OpCodeDescriptor -> String
showPyClass (OpCodeDescriptor name typ doc fields dsc) =
  let
    baseclass
      | name == "OpInstanceMultiAlloc" = "OpInstanceMultiAllocBase"
      | otherwise = "OpCode"
    opDscField
      | null dsc = ""
      | otherwise = "  OP_DSC_FIELD = " ++ show dsc ++ "\n"
    withLU
      | name == "OpTestDummy" = "\n  WITH_LU = False"
      | otherwise = ""
  in
   "class " ++ name ++ "(" ++ baseclass ++ "):" ++ "\n" ++
   pyClassDoc doc ++
   opDscField ++
   "  OP_PARAMS = [" ++
   intercalateIndent (map pyClassField fields) ++
   "\n    ]" ++ "\n" ++
   "  OP_RESULT = " ++ showValue typ ++
   withLU ++ "\n\n"

-- | Generates all opcodes as Python classes.
showPyClasses :: String
showPyClasses = concatMap showPyClass pyClasses
