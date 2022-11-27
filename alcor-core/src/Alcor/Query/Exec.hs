{-| Executing jobs as processes

The protocol works as follows (MP = master process, FP = forked process):

* MP sets its own livelock as the livelock of the job to be executed.

* FP creates its own lock file and sends its name to the MP.

* MP updates the lock file name in the job file and confirms the FP it can
  start.

* FP requests any secret parameters.

* MP sends the secret parameters, if any.

* Both MP and FP close the communication channel.

 -}

{-
-}

module Alcor.Query.Exec
  ( forkJobProcess
  ) where

import Control.Concurrent.Lifted (threadDelay)
import Control.Monad
import Control.Monad.Error
import qualified Data.Map as M
import Data.Maybe (mapMaybe, fromJust)
import System.Environment
import System.IO.Error (annotateIOError, modifyIOError)
import System.IO
import System.Process
import System.Posix.Process
import System.Posix.Signals (sigABRT, sigKILL, sigTERM, signalProcess)
import System.Posix.Types (ProcessID)
import Text.JSON

import qualified AutoConf as AC
import Alcor.BasicTypes
import Alcor.JQueue.Objects
import Alcor.JSON (MaybeForJSON(..))
import Alcor.Logging
import Alcor.Logging.WriterLog
import Alcor.OpCodes
import qualified Alcor.Path as P
import Alcor.Types
import Alcor.UDSServer
import Alcor.Compat (getPid')

connectConfig :: ConnectConfig
connectConfig = ConnectConfig { recvTmo    = 30
                              , sendTmo    = 30
                              }

-- | Catches a potential `IOError` and sets its description via
-- `annotateIOError`. This makes exceptions more informative when they
-- are thrown from an unnamed `Handle`.
rethrowAnnotateIOError :: String -> IO a -> IO a
rethrowAnnotateIOError desc =
  modifyIOError (\e -> annotateIOError e desc Nothing Nothing)

-- | Spawn a subprocess to execute a Job's actual code in the Python
-- interpreter. The subprocess will have its standard input and output
-- connected to a pair of pipes wrapped in a Client instance. Standard error
-- will be inherited from the current process and can be used for early
-- logging, before the executor sets up its own logging.
spawnJobProcess :: JobId -> IO (ProcessID, Client)
spawnJobProcess jid = withErrorLogAt CRITICAL (show jid) $
  do
    use_debug <- isDebugMode
    env_ <- (M.toList . M.insert "GNT_DEBUG" (if use_debug then "1" else "0")
            . M.insert "PYTHONPATH" AC.versionedsharedir
            . M.fromList)
           `liftM` getEnvironment
    execPy <- P.jqueueExecutorPy
    logDebug $ "Executing " ++ AC.pythonPath ++ " " ++ execPy
               ++ " with PYTHONPATH=" ++ AC.versionedsharedir

    (master, child) <- pipeClient connectConfig
    let (rh, wh) = clientToHandle child

    let jobProc = (proc AC.pythonPath [execPy, show (fromJobId jid)]){
        std_in = UseHandle rh,
        std_out = UseHandle wh,
        std_err = Inherit,
        env = Just env_,
        close_fds = True}

    (_, _, _, hchild) <- createProcess jobProc
    pid <- getPid' hchild

    return (fromJust pid, master)


filterSecretParameters :: [QueuedOpCode] -> [MaybeForJSON (JSObject
                                                           (Private JSValue))]
filterSecretParameters =
   map (MaybeForJSON . fmap revealValInJSObject
        . getSecretParams) . mapMaybe (transformOpCode . qoInput)
  where
    transformOpCode :: InputOpCode -> Maybe OpCode
    transformOpCode inputCode =
      case inputCode of
        ValidOpCode moc -> Just (metaOpCode moc)
        _ -> Nothing
    getSecretParams :: OpCode -> Maybe (JSObject (Secret JSValue))
    getSecretParams opcode =
      case opcode of
        (OpInstanceCreate {opOsparamsSecret = x}) -> x
        (OpInstanceReinstall {opOsparamsSecret = x}) -> x
        (OpTestOsParams {opOsparamsSecret = x}) -> x
        _ -> Nothing

-- | Forks the job process and starts processing of the given job.
-- Returns the livelock of the job and its process ID.
forkJobProcess :: (Error e, Show e)
               => QueuedJob -- ^ a job to process
               -> FilePath  -- ^ the daemons own livelock file
               -> (FilePath -> ResultT e IO ())
                  -- ^ a callback function to update the livelock file
                  -- and process id in the job file
               -> ResultT e IO (FilePath, ProcessID)
forkJobProcess job luxiLivelock update = do
  let jidStr = show . fromJobId . qjId $ job

  -- Retrieve secret parameters if present
  let secretParams = encodeStrict . filterSecretParameters . qjOps $ job

  logDebug $ "Setting the lockfile temporarily to " ++ luxiLivelock
             ++ " for job " ++ jidStr
  update luxiLivelock

  ResultT . execWriterLogT . runResultT $ do
    (pid, master) <- liftIO $ spawnJobProcess (qjId job)

    let jobLogPrefix = "[start:job-" ++ jidStr ++ ",pid=" ++ show pid ++ "] "
        logDebugJob = logDebug . (jobLogPrefix ++)

    logDebugJob "Forked a new process"

    let killIfAlive [] = return ()
        killIfAlive (sig : sigs) = do
          logDebugJob "Getting the status of the process"
          status <- tryError . liftIO $ getProcessStatus False True pid
          case status of
            Left e -> logDebugJob $ "Job process already gone: " ++ show e
            Right (Just s) -> logDebugJob $ "Child process status: " ++ show s
            Right Nothing -> do
                logDebugJob $ "Child process running, killing by " ++ show sig
                liftIO $ signalProcess sig pid
                unless (null sigs) $ do
                  threadDelay 100000 -- wait for 0.1s and check again
                  killIfAlive sigs

    let onError = do
          logDebugJob "Closing the pipe to the client"
          withErrorLogAt WARNING "Closing the communication pipe failed"
              (liftIO (closeClient master)) `orElse` return ()
          killIfAlive [sigTERM, sigABRT, sigKILL]

    flip catchError (\e -> onError >> throwError e)
      $ do
      let annotatedIO msg k = do
            logDebugJob msg
            liftIO $ rethrowAnnotateIOError (jobLogPrefix ++ msg) k
      let recv msg = annotatedIO msg (recvMsg master)
          send msg x = annotatedIO msg (sendMsg master x)

      lockfile <- recv "Getting the lockfile of the client"

      logDebugJob $ "Setting the lockfile to the final " ++ lockfile
      toErrorBase $ update lockfile
      send "Confirming the client it can start" ""

      _ <- recv "Waiting for the job to ask for secret parameters"
      send "Writing secret parameters to the client" secretParams

      liftIO $ closeClient master

      return (lockfile, pid)
