{-# LANGUAGE CPP, FlexibleContexts #-}

{-| Provides interface to the 'zlib' library.

-}

{-
-}

module Alcor.Codec
  ( compressZlib
  , decompressZlib
  ) where

import Codec.Compression.Zlib
import qualified Codec.Compression.Zlib.Internal as I
import Control.Monad.Except
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Internal as BL


-- | Compresses a lazy bytestring.
compressZlib :: BL.ByteString -> BL.ByteString
compressZlib = compressWith $
  defaultCompressParams { compressLevel = CompressionLevel 3 }

-- | Decompresses a lazy bytestring, throwing decoding errors using
-- 'throwError'.
decompressZlib :: (MonadError String m) => BL.ByteString -> m BL.ByteString
decompressZlib = I.foldDecompressStreamWithInput
                   (liftM . BL.chunk)
                   return
                   (throwError . (++)"Zlib: " . show)
                   $ I.decompressST I.zlibFormat I.defaultDecompressParams
