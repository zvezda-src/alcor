{-| Crypto-related helper functions.

-}

{-
-}

module Alcor.Hash
  ( computeMac
  , verifyMac
  , HashKey
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.UTF8 as BU
import Crypto.Hash.Algorithms
import Crypto.MAC.HMAC
import Data.Char
import Data.Word

-- | Type alias for the hash key. This depends on the library being
-- used.
type HashKey = [Word8]

-- | Computes the HMAC for a given key/test and salt.
computeMac :: HashKey -> Maybe String -> String -> String
computeMac key salt text =
  let hashable = maybe text (++ text) salt
  in show . hmacGetDigest $
    (hmac (B.pack key) (BU.fromString hashable) :: HMAC SHA1)

-- | Verifies the HMAC for a given message.
verifyMac :: HashKey -> Maybe String -> String -> String -> Bool
verifyMac key salt text digest =
  map toLower digest == computeMac key salt text
