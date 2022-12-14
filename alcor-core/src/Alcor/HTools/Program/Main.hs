{-| Small module holding program definitions.

-}

{-
-}

module Alcor.HTools.Program.Main
  ( personalities
  , main
  ) where

import Control.Exception
import Control.Monad (guard)
import Data.Char (toLower)
import System.Environment
import System.IO
import System.IO.Error (isDoesNotExistError)

import Alcor.Common (formatCommands, PersonalityList)
import Alcor.HTools.CLI (Options, parseOpts, genericOpts)
import qualified Alcor.HTools.Program.Hail as Hail
import qualified Alcor.HTools.Program.Harep as Harep
import qualified Alcor.HTools.Program.Hbal as Hbal
import qualified Alcor.HTools.Program.Hcheck as Hcheck
import qualified Alcor.HTools.Program.Hscan as Hscan
import qualified Alcor.HTools.Program.Hspace as Hspace
import qualified Alcor.HTools.Program.Hsqueeze as Hsqueeze
import qualified Alcor.HTools.Program.Hinfo as Hinfo
import qualified Alcor.HTools.Program.Hroller as Hroller
import Alcor.Utils

-- | Supported binaries.
personalities :: PersonalityList Options
personalities =
  [ ("hail",    (Hail.main,    Hail.options,    Hail.arguments,
                 "Alcor IAllocator plugin that implements the instance\
                 \ placement and movement using the same algorithm as\
                 \ hbal(1)"))
  , ("harep",   (Harep.main,   Harep.options,   Harep.arguments,
                 "auto-repair tool that detects certain kind of problems\
                 \ with instances and applies the allowed set of solutions"))
  , ("hbal",    (Hbal.main,    Hbal.options,    Hbal.arguments,
                 "cluster balancer that looks at the current state of\
                 \ the cluster and computes a series of steps designed\
                 \ to bring the cluster into a better state"))
  , ("hcheck",  (Hcheck.main,  Hcheck.options,  Hcheck.arguments,
                "cluster checker; prints information about cluster's\
                \ health and checks whether a rebalance done using\
                \ hbal would help"))
  , ("hscan",   (Hscan.main,   Hscan.options,   Hscan.arguments,
                "tool for scanning clusters via RAPI and saving their\
                \ data in the input format used by hbal(1) and hspace(1)"))
  , ("hspace",  (Hspace.main,  Hspace.options,  Hspace.arguments,
                "computes how many additional instances can be fit on a\
                \ cluster, while maintaining N+1 status."))
  , ("hinfo",   (Hinfo.main,   Hinfo.options,   Hinfo.arguments,
                "cluster information printer; it prints information\
                \ about the current cluster state and its residing\
                \ nodes/instances"))
  , ("hroller", (Hroller.main, Hroller.options, Hroller.arguments,
                "cluster rolling maintenance helper; it helps scheduling\
                \ node reboots in a manner that doesn't conflict with the\
                \ instances' topology"))
  , ("hsqueeze", (Hsqueeze.main, Hsqueeze.options, Hsqueeze.arguments,
                "cluster dynamic power management;  it powers up and down\
                \ nodes to keep the amount of free online resources in a\
                \ given range"))
  ]

-- | Display usage and exit.
usage :: String -> IO ()
usage name = do
  hPutStrLn stderr $ "Unrecognised personality '" ++ name ++ "'."
  hPutStrLn stderr "This program must be installed under one of the following\
                   \ names:"
  hPutStrLn stderr . unlines $ formatCommands personalities
  exitErr "Please either rename/symlink the program or set\n\
          \the environment variable HTOOLS to the desired role."

main :: IO ()
main = do
  binary <- catchJust (guard . isDoesNotExistError)
            (getEnv "HTOOLS") (const getProgName)
  let name = map toLower binary
  case name `lookup` personalities of
    Nothing -> usage name
    Just (fn, options, arguments, _) -> do
         cmd_args <- getArgs
         real_options <- options
         (opts, args) <- parseOpts cmd_args name (real_options ++ genericOpts)
                           arguments
         fn opts args
