{-# LANGUAGE PatternGuards, ScopedTypeVariables #-}

module Main where

import Control.Concurrent hiding (yield)
import Control.Exception (catch)
import Control.Monad
import Data.Aeson (eitherDecode)
import Data.Foldable
import Data.Map as Map
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import Network (listenOn, PortID(UnixSocket))
import Network.Connection
import Network.Kallisti.Api
import Network.Kallisti.Config
import Network.Kallisti.CryptoBox
import Network.Kallisti.CTools
import Network.Kallisti.Protocol
import Network.Kallisti.Session
import Network.Kallisti.Supervisor
import Network.Kallisti.TAI
import Network.Kallisti.TUNTAP
import Network.Kallisti.Types
import Network.Socket
import Network.Wai.Handler.Warp
import Network.Wai.Handler.WarpTLS
import Network.Wai.Handler.WebSockets
import Network.WebSockets
import Network.WebSockets.Stream hiding (close)
import Pipes
import System.Directory
import System.Environment
import System.Posix.Signals
import System.IO


main :: IO ()
main = do
  args <- getArgs
  case args of
    ["scalarmult"] -> do
      sk <- S.hGet stdin 32
      let Public pk = cryptoBoxScalarMult $ Secret sk
      putStrLn $ "PUBLIC KEY: "++ hexFromKey pk
      putStrLn $ "SECRET KEY: "++ hexFromKey sk
    ["keypair"] -> do
      (Public pk, Secret sk) <- cryptoBoxKeypair
      putStrLn $ "PUBLIC KEY: "++ hexFromKey pk
      putStrLn $ "SECRET KEY: "++ hexFromKey sk
    _ -> do
      cryptoBoxInit
      exit <- newEmptyMVar
      installHandler sigINT  (Catch $ putStr "SIGINT received..."  >> putMVar exit ()) Nothing
      installHandler sigTERM (Catch $ putStr "SIGTERM received..." >> putMVar exit ()) Nothing 
      let cfg = head $ args ++ ["config.json"]
      file <- L.readFile cfg
      case eitherDecode file of
        Left e -> putStrLn $ show e
        Right config -> do
          peerings <- forM (peers config) $ \peer -> do
            clean <- newMVar $ pure ()
            session <- initSession (protocol peer) (publicKey peer) (secretKey config)
            tap <- createTap peer
            establish clean config peer session tap
            let restart p = do
                  new <- takeMVar =<< initSession (protocol p) (publicKey p) (secretKey config)
                  swapMVar session new
                  establish clean config p session tap
            pure (peer, session, tap, clean, restart)
          let start = case (localWebTLS config, localWebUnix config) of
                (False, []) -> runSettings
                (False, sp) -> \s a -> getUnixSocket sp >>= \u -> runSettingsSocket s u a
                (True, []) -> runTLS $ tlsSettings "cert.pem" "key.pem"
                (True, sp)
                  -> \s a -> getUnixSocket sp
                  >>= \u -> runTLSSocket (tlsSettings "cert.pem" "key.pem") s u a
          let sessions = fromList [(publicKey p, (p, s, t)) | (p, s, t, _, _) <- peerings]
          let control  = fromList [(publicKey p, r) | (p, _, _, _, r) <- peerings]
          now <- newMVar =<< getTAI
          forkIO $ start (localWebPort config `setPort` defaultSettings)
            . websocketsOr defaultConnectionOptions (acknowledgement sessions)
            $ api now (sharedKey config) exit control cfg
          threadDelay 1000
          dropPrivileges $ setuid config
          takeMVar exit
          for_ peerings $ \(_,_,_,c,_) -> join $ takeMVar c
          putStrLn "clean exit"

getUnixSocket :: String -> IO Socket
getUnixSocket s = do
  exists <- doesFileExist s 
  when exists $ removeFile s 
  listenOn $ UnixSocket s 

lookupInfo :: String -> Int -> IO AddrInfo
lookupInfo l p = head <$> getAddrInfo (Just hints) (Just l) (Just $ show p)
  where hints = defaultHints { addrFlags = [AI_PASSIVE], addrSocketType = Datagram }

createTap :: Peer -> IO Tap
createTap peer | "tap" == tapMode peer = do
  tap <- openTAP $ interface peer
  bringUp tap
  setMTU tap $ mtu peer
  pure $ Dev tap
createTap peer | "tun" == tapMode peer = do
  tun <- openTUN $ interface peer
  bringUp tun
  setMTU tun $ mtu peer
  pure $ Dev tun
createTap peer | "udp" == take 3 (tapMode peer) = do
  info <- lookupInfo "127.0.0.1" 54712
  remi <- lookupInfo "127.0.0.1" 54713
  sock <- socket (addrFamily info) Datagram defaultProtocol
  bind sock $ addrAddress info
  pure $ Udp (addrAddress remi) sock 
createTap _ = fail "tap device not configured"

acknowledgement :: Map (Public Key) (Peer, Session, Tap) -> ServerApp
acknowledgement sessions pending = do
  connection <- acceptRequest pending
  ident <- Public <$> receiveData connection
  for_ (Map.lookup ident sessions)
    $ \(peer, session, tap) -> acknowledge (protocol peer) session tap connection

negotiation :: Public Key -> Peer -> Session -> Tap -> ClientApp ()
negotiation (Public pk) peer session tap connection = do
  sendBinaryData connection pk
  forkPingThread connection 16
  negotiate (protocol peer) session tap connection


establish :: MVar (IO ()) -> Config -> Peer -> Session -> Tap -> IO ()
establish clean config peer session tap
  | Just remote <- remoteAddr peer
  , "ws" <- take 2 $ protocolIdent peer
  = do
    putStrLn $ "0x" ++ take 8 (let Public pk = publicKey peer in hexFromKey pk)
      ++ ": " ++ interface peer ++ " " ++ protocolIdent peer
      ++ " @ " ++ remote ++ ":" ++ show (remotePort peer)
    join $ takeMVar clean 
    let pk = cryptoBoxScalarMult $ secretKey config
    ws <- forkIO . supervise $ runWS remote (remoteWebPort peer) "/" $ negotiation pk peer session tap
    putMVar clean $ killThread ws
establish _ _ peer _ _
  | "ws" <- take 2 $ protocolIdent peer
  = putStrLn $ "0x" ++ take 8 (let Public pk = publicKey peer in hexFromKey pk)
      ++ ": " ++ interface peer ++ " " ++ protocolIdent peer
establish clean config peer session tap
  | Just local <- localAddr peer
  , Just remote <- remoteAddr peer
  , proto <- protocol peer
  = do
    putStrLn $ "0x" ++ take 8 (let Public pk = publicKey peer in hexFromKey pk)
      ++ ": " ++ interface peer ++ " " ++ protocolIdent peer
      ++ " @ " ++ local ++ ":" ++ show (localPort peer)
      ++ " <-> " ++ remote ++ ":" ++ show (remotePort peer)
    join $ takeMVar clean
    let pk = cryptoBoxScalarMult $ secretKey config
    ws <- forkIO . supervise $ runWS remote (remoteWebPort peer) "/" $ negotiation pk peer session tap
    info <- lookupInfo local $ localPort peer
    remi <- lookupInfo remote $ remotePort peer
    sock <- socket (addrFamily info) Datagram defaultProtocol
    bind sock $ addrAddress info
    connect sock $ addrAddress remi
    unless (udpChecksum peer) $ setSocketOption sock (CustomSockOpt (1, 11)) 1
    i <- forkIO . supervise . runEffect $ receiver proto sock
      >-> decrypt proto session
      >-> sink proto tap
    o <- forkIO . supervise . runEffect $ source proto tap
      >-> encrypt proto session
      >-> launcher proto sock
    putMVar clean $ mapM_ killThread [ws, i, o] >> close sock
establish clean _ peer session tap
  | Just local <- localAddr peer
  , proto <- protocol peer
  = do
    putStrLn $ "0x" ++ take 8 (let Public pk = publicKey peer in hexFromKey pk)
      ++ ": " ++ interface peer ++ " " ++ protocolIdent peer
      ++ " @ " ++ local ++ ":" ++ show (localPort peer)
    join $ takeMVar clean
    info <- lookupInfo local $ localPort peer
    sock <- socket (addrFamily info) Datagram defaultProtocol
    bind sock $ addrAddress info
    unless (udpChecksum peer) $ setSocketOption sock (CustomSockOpt (1, 11)) 1
    i <- forkIO . supervise . runEffect $ receiver proto sock
      >-> decrypt proto session
      >-> floatIn session
      >-> sink proto tap
    o <- forkIO . supervise . runEffect $ source proto tap
      >-> encrypt proto session
      >-> floatOut session
      >-> launcher proto sock
    putMVar clean $ mapM_ killThread [i, o] >> close sock
establish clean config peer session tap
  | Just remote <- remoteAddr peer
  , proto <- protocol peer
  = do
    putStrLn $ "0x" ++ take 8 (let Public pk = publicKey peer in hexFromKey pk)
      ++ ": " ++ interface peer ++ " " ++ protocolIdent peer
      ++ " @ " ++ remote ++ ":" ++ show (remotePort peer)
    join $ takeMVar clean
    let pk = cryptoBoxScalarMult $ secretKey config
    ws <- forkIO . supervise $ runWS remote (remoteWebPort peer) "/" $ negotiation pk peer session tap
    info <- lookupInfo remote $ remotePort peer
    sock <- socket (addrFamily info) Datagram defaultProtocol
    connect sock $ addrAddress info
    unless (udpChecksum peer) $ setSocketOption sock (CustomSockOpt (1, 11)) 1
    i <- forkIO . supervise . runEffect $ receiver proto sock
      >-> decrypt proto session
      >-> sink proto tap
    o <- forkIO . supervise . runEffect $ source proto tap
      >-> encrypt proto session
      >-> launcher proto sock
    putMVar clean $ mapM_ killThread [ws, i, o] >> close sock
establish _ _ _ _ _
  = fail "addr not configured"

floatIn :: Session -> Pipe Packet Packet IO ()
floatIn session = forever $ do
  msg@(_, addr) <- await
  yield msg
  liftIO $ do
    peered <- takeMVar session
    putMVar session $! peered { address = addr }

floatOut :: Session -> Pipe Packet Packet IO ()
floatOut session = forever $ do
  (msg, _) <- await
  addr <- liftIO $ address <$> readMVar session
  case addr of
    SockAddrUnix _ -> pure ()
    _ -> yield (msg, addr)

runWS :: String -> Int -> String -> ClientApp a -> IO a
runWS host port path app = do
  runClient host port path app
  `catch` \(_ :: HandshakeException) -> do
    context <- initConnectionContext
    validation <- maybe False (`elem` ["YES","TRUE"]) <$> lookupEnv "CERT_VALIDATION"
    connection <- connectTo context $ connectionParams $ clientTLSSettings
      { settingDisableCertificateValidation = not validation }
    stream <- makeStream
      (Just <$> connectionGetChunk connection)
      (maybe (pure ()) (mapM_ (connectionPut connection)  . L.toChunks))
    runClientWithStream stream host "/" defaultConnectionOptions [] app 
  where
  clientTLSSettings = TLSSettingsSimple
    { settingDisableCertificateValidation = True
    , settingDisableSession = False
    , settingUseServerName = False
    }
  connectionParams tls = ConnectionParams
    { connectionHostname = host
    , connectionPort = toEnum port
    , connectionUseSecure = Just tls 
    , connectionUseSocks = Just $ SockSettingsEnvironment Nothing
    }

