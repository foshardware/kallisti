{-# LANGUAGE ScopedTypeVariables #-}

module Network.Kallisti.Supervisor where

import Control.Concurrent
import Control.Exception
import Network.WebSockets

supervise :: IO () -> IO ()
supervise action = do
  action `catches`
    [ Handler $ \(e :: IOException) -> putStrLn $ show e 
    , Handler $ \(e :: HandshakeException) -> putStrLn $ show e
    , Handler $ \(e :: ConnectionException) -> putStrLn $ show e
    ]
  threadDelay 4000000
  supervise action

