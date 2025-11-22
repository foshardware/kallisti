
module Network.Kallisti.Types where

import Data.ByteString
import Network.Socket (Socket, SockAddr(..))
import Network.Kallisti.TUNTAP
import Network.Kallisti.WinDivert


type Packet = (ByteString, SockAddr)

data Tap = Dev TAP

