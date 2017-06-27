{-# LANGUAGE ForeignFunctionInterface, EmptyDataDecls, CPP #-}

module Network.Kallisti.WinDivert where

import Data.Bits
import Data.ByteString.Internal
import Data.Word
import Foreign.C.Types
import Foreign.C.String
import Foreign.Ptr
import Foreign.ForeignPtr


data WinDivertDesc
data Frame

newtype Divert = Divert (Ptr WinDivertDesc) deriving Show

data Direction = Inbound | Outbound

instance Enum Direction where
  fromEnum Outbound = 0
  fromEnum Inbound = 1
  toEnum 0 = Outbound
  toEnum _ = Inbound

data Layer = Network | NetworkForward

instance Enum Layer where
  fromEnum Network = 0
  fromEnum NetworkForward = 1
  toEnum 0 = Network
  toEnum _ = NetworkForward

data Flag = Sniff | Drop | NoChecksum

instance Enum Flag where
  fromEnum Sniff = 1
  fromEnum Drop = 2
  fromEnum NoChecksum = 4
  toEnum 1 = Sniff
  toEnum 2 = Drop
  toEnum _ = NoChecksum

maxPktSize :: Int
maxPktSize = 0x10000 - 32

winDivertOpen :: Maybe String -> Layer -> Int -> [Flag] -> Maybe Word32 -> IO Divert
winDivertOpen filterString layer priority flags rewrite =
  withCString (maybe "false" id filterString) $ \f -> Divert
    <$> windivert_open_ffi f
      (fromIntegral $ fromEnum layer)
      (fromIntegral priority)
      (fromIntegral . foldr (.|.) 0 $ fromEnum <$> flags)
      (maybe 0 fromIntegral rewrite)

winDivertClose :: Divert -> IO Bool
winDivertClose (Divert w) = (0 ==) <$> windivert_close_ffi w

setQueueLength :: Divert -> Int -> IO ()
setQueueLength (Divert w) n = windivert_set_param_ffi w 0 $ fromIntegral n

winDivertRecv :: Divert -> IO ByteString
winDivertRecv d = winDivertRecvWithOffset d 0

winDivertRecvWithOffset :: Divert -> Int -> IO ByteString
winDivertRecvWithOffset (Divert w) n = do
  p <- mallocForeignPtrBytes $ maxPktSize + n
  len <- go p
  return $! fromForeignPtr p 0 $ fromIntegral len + n
  where 
    go p = do
      len <- withForeignPtr p $ \p' -> windivert_recv_ffi w (plusPtr p' n) (fromIntegral maxPktSize)
      case len of
        0 -> go p
        _ -> return len

winDivertSend :: Direction -> Divert -> ByteString -> IO Int
winDivertSend dir (Divert w) pkt = case toForeignPtr pkt of
  (p, po, pl) -> withForeignPtr p $ \p' -> fromIntegral
    <$> windivert_send_ffi w (plusPtr p' po) (fromIntegral pl) (fromIntegral $ fromEnum dir)

foreign import CALLCONV "help.h windivert_open" windivert_open_ffi
  :: Ptr CChar -> CInt -> CInt -> CUInt -> CUInt -> IO (Ptr WinDivertDesc)

foreign import CALLCONV "help.h windivert_close" windivert_close_ffi
  :: Ptr WinDivertDesc -> IO CInt

foreign import CALLCONV "help.h windivert_set_param" windivert_set_param_ffi
  :: Ptr WinDivertDesc -> CInt -> CUInt -> IO ()

foreign import CALLCONV "help.h windivert_recv" windivert_recv_ffi
  :: Ptr WinDivertDesc -> Ptr Frame -> CUInt -> IO CInt

foreign import CALLCONV "help.h windivert_send" windivert_send_ffi
  :: Ptr WinDivertDesc -> Ptr Frame -> CUInt -> CUInt -> IO CInt

