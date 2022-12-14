{-# LANGUAGE OverloadedStrings #-}
{-| Logical Volumer information parser

This module holds the definition of the parser that extracts status
information about the logical volumes (LVs) of the system from the output of the
@lvs@ command.

-}
{-
-}
module Alcor.Storage.Lvm.LVParser (lvParser, lvCommand, lvParams) where

import qualified Data.Attoparsec.Text as A
import qualified Data.Attoparsec.Combinator as AC
import Data.Attoparsec.Text (Parser)
import Data.Text (unpack)

import Alcor.Storage.Lvm.Types


-- | The separator of the fields returned by @lvs@
lvsSeparator :: Char
lvsSeparator = ';'

-- * Utility functions

-- | Our own space-skipping function, because A.skipSpace also skips
-- newline characters. It skips ZERO or more spaces, so it does not
-- fail if there are no spaces.
skipSpaces :: Parser ()
skipSpaces = A.skipWhile A.isHorizontalSpace

-- | A parser recognizing a number of bytes, represented as a number preceeded
-- by a separator and followed by the "B" character.
bytesP :: Parser Int
bytesP = A.char lvsSeparator *> A.decimal <* A.char 'B'

-- | A parser recognizing a number discarding the preceeding separator
intP :: Parser Int
intP = A.char lvsSeparator *> A.signed A.decimal

-- | A parser recognizing a string starting with and closed by a separator (both
-- are discarded)
stringP :: Parser String
stringP =
  A.char lvsSeparator *> fmap unpack (A.takeWhile (`notElem`
    [ lvsSeparator
    , '\n']
    ))

-- * Parser implementation

-- | The command providing the data, in the format the parser expects
lvCommand :: String
lvCommand = "lvs"

-- | The parameters for getting the data in the format the parser expects
lvParams :: [String]
lvParams =
  [ "--noheadings"
  , "--units", "B"
  , "--separator", ";"
  , "-o", "lv_uuid,lv_name,lv_attr,lv_major,lv_minor,lv_kernel_major\
    \,lv_kernel_minor,lv_size,seg_count,lv_tags,modules,vg_uuid,vg_name,segtype\
    \,seg_start,seg_start_pe,seg_size,seg_tags,seg_pe_ranges,devices"
  ]

-- | The parser for one line of the diskstatus file.
oneLvParser :: Parser LVInfo
oneLvParser =
  let uuidP = skipSpaces *> fmap unpack (A.takeWhile (/= lvsSeparator))
      nameP = stringP
      attrP = stringP
      majorP = intP
      minorP = intP
      kernelMajorP = intP
      kernelMinorP = intP
      sizeP = bytesP
      segCountP = intP
      tagsP = stringP
      modulesP = stringP
      vgUuidP = stringP
      vgNameP = stringP
      segtypeP = stringP
      segStartP = bytesP
      segStartPeP = intP
      segSizeP = bytesP
      segTagsP = stringP
      segPeRangesP = stringP
      devicesP = stringP
    in
      LVInfo
        <$> uuidP <*> nameP <*> attrP <*> majorP <*> minorP <*> kernelMajorP
        <*> kernelMinorP <*> sizeP <*> segCountP <*> tagsP <*> modulesP
        <*> vgUuidP <*> vgNameP <*> segtypeP <*> segStartP <*> segStartPeP
        <*> segSizeP <*> segTagsP <*> segPeRangesP <*> devicesP 
        <*> return Nothing <* A.endOfLine

-- | The parser for a whole diskstatus file.
lvParser :: Parser [LVInfo]
lvParser = oneLvParser `AC.manyTill` A.endOfInput
