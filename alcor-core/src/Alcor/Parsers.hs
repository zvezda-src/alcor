{-# LANGUAGE OverloadedStrings #-}
{-| Utility functions for several parsers

This module holds the definition for some utility functions for two
parsers.  The parser for the @/proc/stat@ file and the parser for the
@/proc/diskstats@ file.

-}
{-
-}
module Alcor.Parsers where

import qualified Data.Attoparsec.Text as A
import Data.Attoparsec.Text (Parser)
import Data.Text (unpack)

-- * Utility functions

-- | Our own space-skipping function, because A.skipSpace also skips
-- newline characters. It skips ZERO or more spaces, so it does not
-- fail if there are no spaces.
skipSpaces :: Parser ()
skipSpaces = A.skipWhile A.isHorizontalSpace

-- | A parser recognizing a number preceeded by spaces.
numberP :: Parser Int
numberP = skipSpaces *> A.decimal

-- | A parser recognizing a word preceded by spaces, and closed by a space.
stringP :: Parser String
stringP = skipSpaces *> fmap unpack (A.takeWhile $ not . A.isHorizontalSpace)
