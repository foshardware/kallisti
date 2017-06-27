{-# LANGUAGE BangPatterns, PatternGuards #-}

module Network.Kallisti.Protocol.KallisTAI where

import Control.Concurrent hiding (yield)
import Control.Exception
import qualified Data.ByteString as Strict
import Data.ByteString.Internal
import Data.Foldable
import Data.Monoid
import Data.Word
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable
import Network.Kallisti.CryptoBox
import Network.Kallisti.FIFO
import Network.Kallisti.Session
import Network.Kallisti.TAI
import Network.Kallisti.Types
import Network.WebSockets
import Pipes

encrypt, decrypt :: Session -> Pipe Packet Packet IO ()
encrypt s = do
  k <- liftIO $ readMVar s
  auth <- liftIO . takeMVar $ newAuth0 k
  encrypt' (newAuth0 k) auth (nonceSuffix k)
decrypt s = do
  k <- liftIO $ readMVar s
  auth <- liftIO . takeMVar $ newAuth1 k
  decrypt' (newAuth1 k) auth . pack =<< liftIO getTAI
  where pack x = (x, fromList $ replicate 3 x)

wait :: Int
wait = 4

encrypt'
  :: MVar (Forward (Shared Key)) -> Forward (Shared Key) -> Word32
  -> Pipe Packet Packet IO ()
encrypt' mut ki n = do
  (msg, addr) <- await
  k <- liftIO $ maybe ki id <$> tryTakeMVar mut
  now <- liftIO $ getTAICoarseAttoOffset n
  Authenticated result <- liftIO $ fsBoxPeriodUnsafe (taiSeconds now) k (nonce now) msg
  case toForeignPtr result of
    (r, ro, _) -> liftIO . withForeignPtr r $ \r' -> poke (plusPtr r' ro) now
  yield (result, addr)
  encrypt' mut k $ n + 2

decrypt'
  :: MVar (Forward (Shared Key)) -> Forward (Shared Key) -> Window TAI
  -> Pipe Packet Packet IO ()
decrypt' mut ki window@(m, n) = do
  (msg, addr) <- await
  k <- liftIO $ maybe ki id <$> tryTakeMVar mut
  case taiFromByteString msg of
    t | t <= m || elem t n -> decrypt' mut k window
    t -> do
      result <- liftIO $ fsBoxOpenPeriodUnsafe (taiSeconds t) k (nonce t) msg
      case result of
        Nothing -> decrypt' mut k window
        Just r' -> do
          yield (r', addr)
          decrypt' mut k $ dequeue $ enqueue t n

negotiate :: Session -> Tap -> Connection -> IO ()
negotiate session _ connection = do
  putStr "Generating new public key: "
  (Public newPk, newSk) <- cryptoBoxKeypair
  putStrLn $ hexFromKey newPk
  now <- getTAIAttoOffset =<< randomNum
  k <- readMVar session 
  let Authenticated request = cryptoBox (shared k) now newPk
  sendBinaryData connection $ taiBytes now <> request
  putStr "Accepting new public key: "
  response <- Strict.take 64 <$> receiveData connection
  let t' = taiFromByteString response
      period = taiSeconds now + fromIntegral wait
  authenticated <- cryptoBoxOpenUnsafe (shared k) (nonce t') response
  case authenticated of
    Just pk -> do
      old@(Forward u _ _) <- readMVar $ currAuth k
      if period <= u
        then sendClose connection Strict.empty
        else do
          let !new = commitForward period (Public (Strict.drop 32 pk) `cryptoBoxBeforeNM` newSk) old
          for_ [newAuth0, newAuth1, currAuth] $ \v -> tryTakeMVar (v k) *> putMVar (v k) new
          putStrLn . hexFromKey $ Strict.drop 32 pk
    _ -> fail "ECDH exchange: response authentication"

acknowledge :: Session -> Tap -> Connection -> IO ()
acknowledge session _ connection = do
  request <- Strict.take 64 <$> receiveData connection
  let !t' = taiFromByteString request 
      period = taiSeconds t' + fromIntegral wait
  k <- readMVar session 
  authenticated <- cryptoBoxOpenUnsafe (shared k) (nonce t') request
  for_ authenticated $ \pk -> do
    old@(Forward u _ _) <- readMVar $ currAuth k
    if period <= u
      then sendClose connection Strict.empty
      else do
        (Public newPk, newSk) <- cryptoBoxKeypair
        let !new = commitForward period (Public (Strict.drop 32 pk) `cryptoBoxBeforeNM` newSk) old
        now <- getTAIAttoOffset =<< randomNum
        let Authenticated result = cryptoBox (shared k) now newPk
        sendBinaryData connection $ taiBytes now <> result
        for_ [newAuth0, newAuth1, currAuth] $ \v -> tryTakeMVar (v k) *> putMVar (v k) new
        putStrLn $ "Acknowledged new public key: " ++ hexFromKey (Strict.drop 32 pk)

