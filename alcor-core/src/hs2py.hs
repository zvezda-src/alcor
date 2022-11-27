{-# LANGUAGE TemplateHaskell #-}

{-| Haskell to Python opcode generation program.

-}

{-
-}

import Alcor.Hs2Py.GenOpCodes
import Alcor.Hs2Py.ListConstants
import Alcor.THH.PyRPC
import qualified Alcor.WConfd.Core as WConfd
import qualified Alcor.Metad.ConfigCore as Metad

import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

main :: IO ()
main = do
  args <- getArgs
  case args of
    ["--opcodes"] -> putStrLn showPyClasses
    ["--constants"] -> putConstants
    ["--wconfd-rpc"] -> putStrLn $
      $( genPyUDSRpcStubStr "ClientRpcStub" "WCONFD_SOCKET"
                            WConfd.exportedFunctions )
    ["--metad-rpc"] -> putStrLn $
      $( genPyUDSRpcStubStr "ClientRpcStub" "METAD_SOCKET"
                            Metad.exportedFunctions )
    _ -> do
      hPutStrLn stderr "Usage: hs2py --opcodes\
                                  \| --constants\
                                  \| --wconfd-rpc"
      exitFailure
