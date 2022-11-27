{-# LANGUAGE CPP #-}

{- | Compatibility helper module.

This module holds definitions that help with supporting multiple
library versions or transitions between versions.

-}

{-
-}

module Alcor.Compat
  ( filePath'
  , maybeFilePath'
  , toInotifyPath
  , getPid'
  ) where

import qualified Data.ByteString.UTF8 as UTF8
import System.FilePath (FilePath)
import System.Posix.ByteString.FilePath (RawFilePath)
import qualified System.INotify
import qualified Text.JSON
import qualified Control.Monad.Fail as Fail
import System.Process.Internals
import System.Posix.Types (CPid (..))
import System.Process (getPid)
import Control.Concurrent.Lifted (readMVar)

-- | Wrappers converting ByteString filepaths to Strings and vice versa
--
-- hinotify 0.3.10 switched to using RawFilePaths instead of FilePaths, the
-- former being Data.ByteString and the latter String.
filePath' :: System.INotify.Event -> FilePath
filePath' = UTF8.toString . System.INotify.filePath

maybeFilePath' :: System.INotify.Event -> Maybe FilePath
maybeFilePath' ev = UTF8.toString <$> System.INotify.maybeFilePath ev

toInotifyPath :: FilePath -> RawFilePath
toInotifyPath = UTF8.fromString
filePath' :: System.INotify.Event -> FilePath
filePath' = System.INotify.filePath

maybeFilePath' :: System.INotify.Event -> Maybe FilePath
maybeFilePath' = System.INotify.maybeFilePath

toInotifyPath :: FilePath -> FilePath
toInotifyPath = id

-- | MonadFail.Fail instance definitions for JSON results
--
-- Required as of GHC 8.6 because MonadFailDesugaring is on by
-- default:
-- <https://gitlab.haskell.org/ghc/ghc/wikis/migration/8.6>. Added
-- upstream in version 0.10.
instance Fail.MonadFail Text.JSON.Result where
  fail = Fail.fail

-- | Process 1.6.3. introduced the getPid function, for older versions
-- provide an implemention here (https://github.com/haskell/process/pull/109)
type Pid = CPid
getPid' :: ProcessHandle -> IO (Maybe Pid)
getPid' = getPid
getPid' (ProcessHandle mh _) = do
  p_ <- readMVar mh
  case p_ of
    OpenHandle pid -> return $ Just pid
    _ -> return Nothing
