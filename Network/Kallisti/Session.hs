
module Network.Kallisti.Session where

import Control.Concurrent
import Data.Word
import Network.Kallisti.CryptoBox
import Network.Socket (SockAddr(..))


type Session = MVar SessionState

data SessionState = Session
  { address :: !SockAddr
  , shared  :: Shared Key
  , currAuth :: MVar (Forward (Shared Key))
  , newAuth0 :: MVar (Forward (Shared Key))
  , newAuth1 :: MVar (Forward (Shared Key))
  , nonceSuffix :: Word32
  }

newSession :: IO Session
newSession = do
  c <- newEmptyMVar
  n <- newEmptyMVar
  o <- newEmptyMVar
  newMVar $ Session
    { address = SockAddrUnix []
    , shared  = undefined
    , currAuth = c
    , newAuth0 = n
    , newAuth1 = o
    , nonceSuffix = 0
    }

