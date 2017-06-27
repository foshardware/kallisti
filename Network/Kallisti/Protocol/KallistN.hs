{-# LANGUAGE BangPatterns, PatternGuards #-}

module Network.Kallisti.Protocol.KallistN where

import Control.Concurrent hiding (yield)
import Data.ByteString.Internal
import Data.Word
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable
import Network.Kallisti.Builder
import Network.Kallisti.CryptoBox
import Network.Kallisti.FIFO
import Network.Kallisti.Session
import Network.Kallisti.Types
import Pipes

encrypt, decrypt :: Session -> Pipe Packet Packet IO ()
encrypt s = do
  k <- liftIO $ readMVar s
  Forward _ key _ <- liftIO . takeMVar $ newAuth0 k
  encrypt' key . fromIntegral $ nonceSuffix k
decrypt s = do
  k <- liftIO $ readMVar s
  Forward _ key _ <- liftIO . takeMVar $ newAuth0 k
  decrypt' key (0, FIFO [] $ replicate 3 0)

encrypt' :: Shared Key -> Word64 -> Pipe Packet Packet IO ()
encrypt' _ n | n > maxBound - 2 = pure ()
encrypt' k n = do
  (msg, addr) <- await
  Authenticated result <- liftIO $ cryptoBoxUnsafe k (fromWord64 n) msg
  case toForeignPtr result of
    (r, ro, _) -> liftIO $ withForeignPtr r $ \r' -> poke (plusPtr r' $ ro + 8) n
  yield (result, addr)
  encrypt' k $ n + 2

decrypt' :: Shared Key -> Window Word64 -> Pipe Packet Packet IO ()
decrypt' k window@(m, n) = do
  (msg, addr) <- await
  case toForeignPtr msg of
    (p, po, _) -> do
      t <- liftIO $ withForeignPtr p $ \p' -> peek (plusPtr p' $ po + 8)
      if t <= m || elem t n
        then decrypt' k window
        else do
          result <- liftIO $ cryptoBoxOpenUnsafe k (fromWord64 t) msg
          case result of
            Just r' -> do
              yield (r', addr)
              decrypt' k $ dequeue $ enqueue t n
            _ -> decrypt' k window

