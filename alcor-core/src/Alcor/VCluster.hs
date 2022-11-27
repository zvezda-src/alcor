{-| Utilities for virtual clusters.

-}

{-
-}

module Alcor.VCluster
  ( makeVirtualPath
  ) where

import Control.Monad (liftM)
import Data.Set (member)
import System.Posix.Env (getEnv)
import System.FilePath.Posix

import Alcor.ConstantUtils (unFrozenSet)
import Alcor.Constants

getRootDirectory :: IO (Maybe FilePath)
getRootDirectory = fmap normalise `liftM` getEnv vClusterRootdirEnvname

-- | Pure computation of the virtual path from the original path
-- and the vcluster root
virtualPath :: FilePath -> FilePath -> FilePath
virtualPath fpath root =
  let relpath = makeRelative root fpath
  in if member fpath (unFrozenSet vClusterVpathWhitelist)
       then fpath
       else vClusterVirtPathPrefix </> relpath

-- | Given a path, make it a virtual one, if in a vcluster environment.
-- Otherwise, return unchanged.
makeVirtualPath :: FilePath -> IO FilePath
makeVirtualPath fpath = maybe fpath (virtualPath fpath) `liftM` getRootDirectory
