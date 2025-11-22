{-# LANGUAGE TypeApplications #-}

module Network.Kallisti.Protocol.WSNaClN where

import Control.Concurrent hiding (yield)
import Control.Exception (try, AsyncException)
import Control.Monad
import Data.ByteString (ByteString)
import Data.Word
import Network.Kallisti.Builder
import Network.Kallisti.CryptoBox
import Network.Kallisti.Protocol.WSRaw (dropSomeTcp)
import Network.Kallisti.Session
import Network.Kallisti.TUNTAP
import Network.Kallisti.Types
import qualified Network.Socket.ByteString as Udp
import Network.WebSockets
import Pipes
import qualified Pipes.Prelude as Pipe
import System.Environment

source :: Shared Key -> Tap -> Connection -> Word64 -> IO ()
source k tun connection n = do
  d <- maybe 0 read <$> lookupEnv "TCPDROP"
  when (d > 0) . putStrLn $ "TCPDROP: " ++ show d
  runEffect $ Pipe.repeatM (readTap tun)
    >-> dropSomeTcp d (d - 4)
    >-> encrypt k n
    >-> Pipe.mapM_ (sendBinaryData connection)
  where
    readTap (Dev t) = readTUN t

encrypt :: Shared Key -> Word64 -> Pipe ByteString ByteString IO ()
encrypt _ n | n > maxBound - 2 = pure ()
encrypt k n = do
  Authenticated encrypted <- cryptoBox k (fromWord64 n) <$> await
  yield encrypted
  encrypt k $ n + 2

sink :: Shared Key -> Connection -> Tap -> Word64 -> IO ()
sink k connection tun n = do
  runEffect $ Pipe.repeatM (receiveData connection)
    >-> decrypt k n
    >-> Pipe.mapM_ (writeTap tun)
  where
    writeTap (Dev t) bs = void $ writeTUN t bs

decrypt :: Shared Key -> Word64 -> Pipe ByteString ByteString IO ()
decrypt k n = do
  encrypted <- await
  case cryptoBoxOpen k (fromWord64 n) encrypted of
    Nothing -> decrypt k n
    Just decrypted -> do
      yield decrypted
      decrypt k $ n + 2

negotiate :: Session -> Tap -> Connection -> IO ()
negotiate session tun connection = do
  Forward _ k _ <- takeMVar . newAuth0 =<< readMVar session
  end <- newEmptyMVar
  i <- forkFinally (source k tun connection 1) $ \_ -> putMVar end ()
  o <- forkFinally   (sink k connection tun 0) $ \_ -> putMVar end ()
  try @AsyncException $ takeMVar end
  mapM_ killThread [i, o]
negotiate _ _ _ = pure ()

acknowledge :: Session -> Tap -> Connection -> IO ()
acknowledge session tun connection = do
  Forward _ k _ <- takeMVar . newAuth1 =<< readMVar session
  end <- newEmptyMVar
  i <- forkFinally (source k tun connection 0) $ \_ -> putMVar end ()
  o <- forkFinally   (sink k connection tun 1) $ \_ -> putMVar end ()
  try @AsyncException $ takeMVar end
  mapM_ killThread [i, o]
acknowledge _ _ _ = pure ()

