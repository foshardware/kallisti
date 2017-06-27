{-# LANGUAGE TypeApplications #-}

module Network.Kallisti.Protocol.WSRaw where

import Control.Concurrent hiding (yield)
import Control.Exception (try, AsyncException)
import Control.Monad
import Data.Attoparsec.ByteString (Parser)
import qualified Data.Attoparsec.ByteString as Parser
import Data.Bits
import Data.ByteString (ByteString)
import Network.Kallisti.Session
import Network.Kallisti.TUNTAP
import Network.Kallisti.Types
import Network.WebSockets
import Pipes
import qualified Pipes.Prelude as Pipe
import System.Environment

source ::  TUN -> Connection -> IO ()
source tun connection = do
  d <- maybe 0 read <$> lookupEnv "TCPDROP"
  when (d > 0) . putStrLn $ "TCPDROP: " ++ show d
  runEffect $ Pipe.repeatM (readTUN tun)
    >-> dropSomeTcp d (d - 4)
    >-> Pipe.mapM_ (sendBinaryData connection)

sink :: Connection -> TUN -> IO ()
sink connection tun
  = runEffect $ Pipe.repeatM (receiveData connection) >-> Pipe.mapM_ (void . writeTUN tun)

negotiate :: Session -> Tap -> Connection -> IO ()
negotiate _ (Dev tun) connection = do
  end <- newEmptyMVar
  i <- forkFinally (source tun connection) $ \_ -> putMVar end ()
  o <- forkFinally   (sink connection tun) $ \_ -> putMVar end ()
  try @AsyncException $ takeMVar end
  mapM_ killThread [i, o]
negotiate _ _ _ = pure ()

acknowledge :: Session -> Tap -> Connection -> IO ()
acknowledge _ (Dev tun) connection = do
  end <- newEmptyMVar
  i <- forkFinally (source tun connection) $ \_ -> putMVar end ()
  o <- forkFinally   (sink connection tun) $ \_ -> putMVar end ()
  try @AsyncException $ takeMVar end
  mapM_ killThread [i, o]
acknowledge _ _ _ = pure ()


dropSomeTcp :: Int -> Int -> Pipe ByteString ByteString IO ()
dropSomeTcp 0 _ = cat
dropSomeTcp d n = do
  packet <- await
  case mod n d <$ Parser.parseOnly tcp packet of
    Left  _ -> yield packet >> dropSomeTcp d n
    Right 0 -> dropSomeTcp d (n + 1)
    Right _ -> yield packet >> dropSomeTcp d (n + 1)

tcp :: Parser ()
tcp = do
  version <- Parser.anyWord8
  case version .&. 0xf0 of
    0x40 -> Parser.take 8
    0x60 -> Parser.take 5
    _ -> mzero
  protocol <- Parser.anyWord8
  guard $ 0x06 == protocol

