{-# LANGUAGE OverloadedStrings #-}
{-| Diskstats proc file parser

This module holds the definition of the parser that extracts status
information about the disks of the system from the @/proc/diskstats@ file.

-}
{-
-}
module Alcor.Storage.Diskstats.Parser (diskstatsParser) where

import qualified Data.Attoparsec.Text as A
import qualified Data.Attoparsec.Combinator as AC
import Data.Attoparsec.Text (Parser)

import Alcor.Parsers
import Alcor.Storage.Diskstats.Types

-- * Parser implementation

-- | The parser for one line of the diskstatus file.
oneDiskstatsParser :: Parser Diskstats
oneDiskstatsParser =
  let majorP = numberP
      minorP = numberP
      nameP = stringP
      readsNumP = numberP
      mergedReadsP = numberP
      secReadP = numberP
      timeReadP = numberP
      writesP = numberP
      mergedWritesP = numberP
      secWrittenP = numberP
      timeWriteP = numberP
      iosP = numberP
      timeIOP = numberP
      wIOmillisP = numberP
  in
    Diskstats <$> majorP <*> minorP <*> nameP <*> readsNumP <*> mergedReadsP
      <*> secReadP <*> timeReadP <*> writesP <*> mergedWritesP <*> secWrittenP
      <*> timeWriteP <*> iosP <*> timeIOP <*> wIOmillisP <* A.endOfLine

-- | The parser for a whole diskstatus file.
diskstatsParser :: Parser [Diskstats]
diskstatsParser = oneDiskstatsParser `AC.manyTill` A.endOfInput
