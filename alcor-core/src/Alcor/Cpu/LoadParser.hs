{-# LANGUAGE OverloadedStrings #-}
{-| /proc/stat file parser

This module holds the definition of the parser that extracts information
about the CPU load of the system from the @/proc/stat@ file.

-}
{-
-}
module Alcor.Cpu.LoadParser (cpustatParser) where

import Control.Applicative ((<|>))
import qualified Data.Attoparsec.Text as A
import qualified Data.Attoparsec.Combinator as AC
import Data.Attoparsec.Text (Parser)

import Alcor.Parsers
import Alcor.Cpu.Types

-- * Parser implementation

-- | The parser for one line of the CPU status file.
oneCPUstatParser :: Parser CPUstat
oneCPUstatParser =
  let nameP = stringP
      userP = numberP
      niceP = numberP
      systemP = numberP
      idleP = numberP
      iowaitP = numberP
      irqP = numberP
      softirqP = numberP
      stealP = numberP
      guestP = numberP
      guest_niceP = numberP
  in
    CPUstat <$> nameP <*> userP <*> niceP <*> systemP <*> idleP <*> iowaitP
            <*> irqP <*> softirqP <*> stealP <*> guestP <*> guest_niceP
            <* A.endOfLine

-- | When this is satisfied all the lines containing information about
-- the CPU load are parsed.
intrFound :: Parser ()
intrFound = (A.string "intr" *> return ())
             <|> (A.string "page" *> return ())
             <|> (A.string "swap" *> return ())

-- | The parser for the fragment of CPU status file containing
-- information about the CPU load.
cpustatParser :: Parser [CPUstat]
cpustatParser = oneCPUstatParser `AC.manyTill` intrFound
