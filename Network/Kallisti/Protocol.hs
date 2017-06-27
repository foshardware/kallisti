{-# LANGUAGE TupleSections #-}

module Network.Kallisti.Protocol where

import Control.Monad
import Control.Concurrent hiding (yield)
import Data.ByteString as Strict
import Data.Foldable
import Network.Kallisti.CryptoBox
import Network.Kallisti.Session
import Network.Kallisti.TAI
import Network.Kallisti.Socket
import Network.Kallisti.TUNTAP
import Network.Kallisti.Types
import Network.Kallisti.WinDivert
import qualified Network.Kallisti.Protocol.NaCl0 as NaCl0
import qualified Network.Kallisti.Protocol.NaClTAI as NaClTAI
import qualified Network.Kallisti.Protocol.KallisTAI as KallisTAI
import qualified Network.Kallisti.Protocol.KallisTAI as KallistN
import qualified Network.Kallisti.Protocol.WSRaw as WSRaw
import qualified Network.Kallisti.Protocol.WSNaClN as WSNaClN
import Network.Socket (Socket, SockAddr(..))
import Network.Socket.ByteString
import Network.WebSockets (Connection)
import Pipes
import qualified Pipes.Prelude as P


datagramSize :: Int
datagramSize = 2032

data Protocol = Protocol
  { source :: Tap -> Producer Packet IO ()
  , sink :: Tap -> Consumer Packet IO ()
  , encrypt :: Session -> Pipe Packet Packet IO ()
  , decrypt :: Session -> Pipe Packet Packet IO ()
  , receiver :: Socket -> Producer Packet IO ()
  , launcher :: Socket -> Consumer Packet IO ()
  , negotiate :: Session -> Tap -> Connection -> IO ()
  , acknowledge :: Session -> Tap -> Connection -> IO ()
  , initSession :: Public Key -> Secret Key -> IO Session
  }

raw :: Protocol
raw = Protocol
  { source = P.repeatM . fmap (, SockAddrUnix []) . readTap
  , sink = \t -> P.mapM_ $ writeTap t . fst
  , encrypt = const cat
  , decrypt = const cat
  , receiver = \s -> P.repeatM $ recvFromWithOffset s (datagramSize + 16) 0
  , launcher = \s -> P.mapM_ $ \(msg, addr) -> sendAll' s msg addr
  , negotiate = \_ _ _ -> pure ()
  , acknowledge = \_ _ _ -> pure ()
  , initSession = \_ _ -> newSession
  }
  where
    readTap (Dev t) = readTAP t
    readTap (Udp _ s) = recv s 2048
    readTap (Win d) = winDivertRecv d
    readTap (Unix s) = recv s 2048

    writeTap (Dev t) bs = void $ writeTAP t bs
    writeTap (Udp a s) bs = void $ sendAllTo s bs a
    writeTap (Win d) bs = void $ winDivertSend Inbound d bs
    writeTap (Unix s) bs = void $ send s bs

nacl0 :: Protocol
nacl0 = raw
  { source = P.repeatM . fmap (, SockAddrUnix []) . readTap
  , sink = \t -> P.mapM_ $ writeTap t . Strict.drop 32 . fst
  , encrypt = NaCl0.encrypt
  , decrypt = NaCl0.decrypt
  , receiver = \s -> P.repeatM $ recvFromWithOffset s datagramSize 16
  , launcher = \s -> P.mapM_ $ \(msg, addr) -> sendAll' s (Strict.drop 16 msg) addr
  , initSession = \pk sk -> do
      s' <- newSession
      modifyMVar_ s' $ \s -> pure s { shared = cryptoBoxBeforeNM pk sk }
      pure s'
  }
  where
    readTap (Dev t) = readTAPWithOffset t 32
    readTap (Udp _ s) = recvWithOffset s 32 2016
    readTap (Win d) = winDivertRecvWithOffset d 32
    readTap (Unix s) = error "read from unix socket not implemented"

    writeTap (Dev t) bs = void $ writeTAP t bs
    writeTap (Udp a s) bs = void $ sendAllTo s bs a
    writeTap (Win d) bs = void $ winDivertSend Inbound d bs
    writeTap (Unix s) bs = void $ send s bs

naclTAI :: Protocol
naclTAI = nacl0
  { encrypt = NaClTAI.encrypt
  , decrypt = NaClTAI.decrypt
  , receiver = \s -> P.repeatM $ recvFromWithOffset s (datagramSize + 16) 0
  , launcher = \s -> P.mapM_ $ \(msg, addr) -> sendAll' s msg addr
  , initSession = \pk sk -> do
      s' <- initSession nacl0 pk sk
      modifyMVar_ s' $ \s -> pure s { nonceSuffix = if pk < cryptoBoxScalarMult sk then 0 else 1 }
      pure s'
  }

kallistai :: Protocol
kallistai = naclTAI
  { encrypt = KallisTAI.encrypt
  , decrypt = KallisTAI.decrypt
  , negotiate = \s t c -> forever $ KallisTAI.negotiate s t c >> threadDelay (512*1024*1024)
  , acknowledge = \s t c -> forever $ KallisTAI.acknowledge s t c
  , initSession = \pk sk -> do 
      now <- taiSeconds <$> getTAI
      s' <- initSession naclTAI pk sk
      ca <- currAuth <$> readMVar s'
      putMVar ca =<< initForwardSecret now
      pure s'
  }

kallistn :: Protocol
kallistn = kallistai
  { encrypt = KallistN.encrypt
  , decrypt = KallistN.decrypt
  , negotiate = \s t c -> KallisTAI.negotiate s t c >> forever (threadDelay maxBound)
  , acknowledge = KallisTAI.acknowledge
  }

wsRaw :: Protocol
wsRaw = raw
  { source = \_ -> pure ()
  , sink = \_ -> pure ()
  , receiver = \_ -> pure ()
  , launcher = \_ -> pure ()
  , negotiate = WSRaw.negotiate
  , acknowledge = WSRaw.acknowledge
  }

wsNaclN :: Protocol
wsNaclN = wsRaw
  { negotiate = \s t c -> KallisTAI.negotiate s t c >> WSNaClN.negotiate s t c
  , acknowledge = \s t c -> KallisTAI.acknowledge s t c >> WSNaClN.acknowledge s t c
  , initSession = initSession kallistai
  }

instance Read Protocol where
  readsPrec _ s = [(maybe naclTAI id $ lookup s protocols, [])]

protocols :: [(String, Protocol)]
protocols =
  [ ("raw", raw)
  , ("nacl0", nacl0)
  , ("nacltai", naclTAI)
  , ("nacl-tai", naclTAI)
  , ("kallistai", kallistai)
  , ("kallist0", kallistai)
  , ("kallistn", kallistn)
  , ("kallist1", kallistn)
  , ("wsraw", wsRaw)
  , ("ws-raw", wsRaw)
  , ("wsnacln", wsNaclN)
  , ("ws-nacln", wsNaclN)
  ]

sendAll' :: Socket -> ByteString -> SockAddr -> IO ()
sendAll' s msg (SockAddrUnix _) = sendAll s msg
sendAll' s msg addr = sendAllTo s msg addr

