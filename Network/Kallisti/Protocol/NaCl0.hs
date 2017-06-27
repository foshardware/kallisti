
module Network.Kallisti.Protocol.NaCl0 where

import Control.Concurrent.MVar
import Control.Monad
import Data.Foldable
import Network.Kallisti.CryptoBox
import Network.Kallisti.Session
import Network.Kallisti.Types
import Pipes


encrypt, decrypt :: Session -> Pipe Packet Packet IO ()
encrypt s = encrypt' . shared =<< liftIO (readMVar s)
decrypt s = decrypt' . shared =<< liftIO (readMVar s)

encrypt' :: Shared Key -> Pipe Packet Packet IO ()
encrypt' k = forever $ do
  (msg, addr) <- await
  Authenticated result <- liftIO $ cryptoBoxUnsafe k (zeroBytes 24) msg
  yield (result, addr)

decrypt' :: Shared Key -> Pipe Packet Packet IO ()
decrypt' k = forever $ do
  (msg, addr) <- await
  result <- liftIO $ cryptoBoxOpenUnsafe k (zeroBytes 24) msg
  for_ result $ \r -> yield (r, addr)

