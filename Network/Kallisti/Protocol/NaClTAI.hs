{-# LANGUAGE PatternGuards #-}

module Network.Kallisti.Protocol.NaClTAI where

import Control.Concurrent.MVar
import Data.ByteString.Internal
import Data.Word
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Storable
import Network.Kallisti.CryptoBox
import Network.Kallisti.FIFO
import Network.Kallisti.Session
import Network.Kallisti.TAI
import Network.Kallisti.Types
import Pipes


encrypt, decrypt :: Session -> Pipe Packet Packet IO ()
encrypt s = do
  k <- liftIO $ readMVar s
  encrypt' (shared k) (nonceSuffix k)
decrypt s = do
  k <- liftIO $ readMVar s
  decrypt' (shared k) . pack =<< liftIO getTAI
  where pack x = (x, fromList $ replicate 3 x)

encrypt' :: Shared Key -> Word32 -> Pipe Packet Packet IO ()
encrypt' k n = do
  (msg, addr) <- await
  now <- liftIO $ getTAICoarseAttoOffset n
  Authenticated result <- liftIO $ cryptoBoxUnsafe k (nonce now) msg
  case toForeignPtr result of
    (r, ro, _) -> liftIO . withForeignPtr r $ \r' -> poke (plusPtr r' ro) now
  yield (result, addr)
  encrypt' k $ n + 2

decrypt' :: Shared Key -> Window TAI -> Pipe Packet Packet IO ()
decrypt' k window@(m, n) = do
  (msg, addr) <- await
  case taiFromByteString msg of
    t | t <= m || elem t n -> decrypt' k window
    t -> do
      result <- liftIO $ cryptoBoxOpenUnsafe k (nonce t) msg
      case result of
        Nothing -> decrypt' k window
        Just r' -> do
          yield (r', addr)
          decrypt' k $ dequeue $ enqueue t n

