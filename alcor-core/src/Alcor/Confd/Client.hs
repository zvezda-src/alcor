{-| Implementation of the Alcor Confd client functionality.

-}

{-
-}

module Alcor.Confd.Client
  ( getConfdClient
  , query
  ) where

import Control.Concurrent
import Control.Exception (bracket)
import Control.Monad
import qualified Data.ByteString.Char8 as Char8
import Data.List
import Data.Maybe
import qualified Network.Socket as S
import Network.Socket.ByteString (sendTo, recv)
import System.Posix.Time
import qualified Text.JSON as J

import Alcor.BasicTypes
import Alcor.Confd.Types
import Alcor.Confd.Utils
import qualified Alcor.Constants as C
import Alcor.Hash
import Alcor.Ssconf
import Alcor.Utils

-- | Builds a properly initialized ConfdClient.
-- The parameters (an IP address and the port number for the Confd client
-- to connect to) are mainly meant for testing purposes. If they are not
-- provided, the list of master candidates and the default port number will
-- be used.
getConfdClient :: Maybe String -> Maybe Int -> IO ConfdClient
getConfdClient addr portNum = S.withSocketsDo $ do
  hmac <- getClusterHmac
  candList <- getMasterCandidatesIps Nothing
  peerList <-
    case candList of
      (Ok p) -> return p
      (Bad msg) -> fail msg
  let addrList = maybe peerList (:[]) addr
      port = fromMaybe C.defaultConfdPort portNum
  return . ConfdClient hmac addrList $ fromIntegral port

-- | Sends a query to all the Confd servers the client is connected to.
-- Returns the most up-to-date result according to the serial number,
-- chosen between those received before the timeout.
query :: ConfdClient -> ConfdRequestType -> ConfdQuery -> IO (Maybe ConfdReply)
query client crType cQuery = do
  semaphore <- newMVar ()
  answer <- newMVar Nothing
  let dest = [(host, serverPort client) | host <- peers client]
      hmac = hmacKey client
      jobs = map (queryOneServer semaphore answer crType cQuery hmac) dest
      watchdog reqAnswers = do
        threadDelay $ 1000000 * C.confdClientExpireTimeout
        _ <- swapMVar reqAnswers 0
        putMVar semaphore ()
      waitForResult reqAnswers = do
        _ <- takeMVar semaphore
        l <- takeMVar reqAnswers
        unless (l == 0) $ do
          putMVar reqAnswers $ l - 1
          waitForResult reqAnswers
  reqAnswers <- newMVar . min C.confdDefaultReqCoverage $ length dest
  workers <- mapM forkIO jobs
  watcher <- forkIO $ watchdog reqAnswers
  waitForResult reqAnswers
  mapM_ killThread $ watcher:workers
  takeMVar answer

-- | Updates the reply to the query. As per the Confd design document,
-- only the reply with the highest serial number is kept.
updateConfdReply :: ConfdReply -> Maybe ConfdReply -> Maybe ConfdReply
updateConfdReply newValue Nothing = Just newValue
updateConfdReply newValue (Just currentValue) = Just $
  if confdReplyStatus newValue == ReplyStatusOk
      && (confdReplyStatus currentValue /= ReplyStatusOk
          || confdReplySerial newValue > confdReplySerial currentValue)
    then newValue
    else currentValue

-- | Send a query to a single server, waits for the result and stores it
-- in a shared variable. Then, sends a signal on another shared variable
-- acting as a semaphore.
-- This function is meant to be used as one of multiple threads querying
-- multiple servers in parallel.
queryOneServer
  :: MVar ()                 -- ^ The semaphore that will be signalled
  -> MVar (Maybe ConfdReply) -- ^ The shared variable for the result
  -> ConfdRequestType        -- ^ The type of the query to be sent
  -> ConfdQuery              -- ^ The content of the query
  -> HashKey                 -- ^ The hmac key to sign the message
  -> (String, S.PortNumber)  -- ^ The address and port of the server
  -> IO ()
queryOneServer semaphore answer crType cQuery hmac (host, port) = do
  request <- newConfdRequest crType cQuery
  timestamp <- fmap show epochTime
  let signedMsg =
        signMessage hmac timestamp (J.encodeStrict request)
      completeMsg = C.confdMagicFourcc ++ J.encodeStrict signedMsg
  addr <- resolveAddr (fromIntegral port) host
  (af_family, sockaddr) <-
    exitIfBad "Unable to resolve the IP address" addr
  replyMsg <- bracket (S.socket af_family S.Datagram S.defaultProtocol) S.close
                $ \s -> do
    _ <- sendTo s (Char8.pack completeMsg) sockaddr
    Char8.unpack <$> recv s C.maxUdpDataSize
  parsedReply <-
    if C.confdMagicFourcc `isPrefixOf` replyMsg
      then return . parseReply hmac (drop 4 replyMsg) $ confdRqRsalt request
      else fail "Invalid magic code!"
  reply <-
    case parsedReply of
      Ok (_, r) -> return r
      Bad msg -> fail msg
  modifyMVar_ answer $! return . updateConfdReply reply
  putMVar semaphore ()
