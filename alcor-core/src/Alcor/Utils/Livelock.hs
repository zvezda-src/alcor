{-| Utilities related to livelocks and death detection

-}

{-
-}

module Alcor.Utils.Livelock
  ( Livelock
  , mkLivelockFile
  , listLiveLocks
  , isDead
  ) where

import qualified Control.Exception as E
import Control.Monad
import Control.Monad.Error
import System.Directory (doesFileExist, getDirectoryContents)
import System.FilePath.Posix ((</>))
import System.IO
import System.Posix.IO
import System.Posix.Types (Fd)
import System.Time (ClockTime(..), getClockTime)

import Alcor.BasicTypes
import Alcor.Logging
import Alcor.Path (livelockFile, livelockDir)
import Alcor.Utils (lockFile)

type Livelock = FilePath

-- | Appends the current time to the given prefix, creates
-- the lockfile in the appropriate directory, and locks it.
-- Returns its full path and the file's file descriptor.
mkLivelockFile :: (Error e, MonadError e m, MonadIO m)
               => FilePath -> m (Fd, Livelock)
mkLivelockFile prefix = do
  (TOD secs _) <- liftIO getClockTime
  lockfile <- liftIO . livelockFile $ prefix ++ "_" ++ show secs
  fd <- liftIO (lockFile lockfile) >>= \r -> case r of
          Bad msg   -> failError $ "Locking the livelock file " ++ lockfile
                                   ++ ": " ++ msg
          Ok fd     -> return fd
  return (fd, lockfile)

-- | List currently existing livelocks. Underapproximate if
-- some error occurs.
listLiveLocks :: IO [FilePath]
listLiveLocks =
  fmap (genericResult (const [] :: IOError -> [FilePath]) id)
  . runResultT . liftIO $ do
    dir <- livelockDir
    entries <- getDirectoryContents dir
    filterM doesFileExist $ map (dir </>) entries

-- | Detect whether a the process identified by the given path
-- does not exist any more. This function never fails and only
-- returns True if it has positive knowledge that the process
-- does not exist any more (i.e., if it managed successfully
-- obtain a shared lock on the file).
isDead :: Livelock -> IO Bool
isDead fpath = fmap (isOk :: Result () -> Bool) . runResultT . liftIO $ do
  filepresent <- doesFileExist fpath
  when filepresent
    . E.bracket (openFd fpath ReadOnly Nothing defaultFileFlags) closeFd
                $ \fd -> do
                    logDebug $ "Attempting to get a lock of " ++ fpath
                    setLock fd (ReadLock, AbsoluteSeek, 0, 0)
                    logDebug "Got the lock, the process is dead"
