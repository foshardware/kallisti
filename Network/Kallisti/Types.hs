
module Network.Kallisti.Types where

import Data.ByteString
import Network.Socket (Socket, SockAddr(..))
import Network.Kallisti.TUNTAP

type Packet = (ByteString, SockAddr)

data Tap = Dev TAP

