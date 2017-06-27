{-# LANGUAGE ForeignFunctionInterface, EmptyDataDecls, CPP #-}

module Network.Kallisti.TUNTAP where

import Control.Concurrent (threadWaitRead)
import Foreign.C.Types
import Foreign.C.String
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Marshal.Array
import Data.Word
import Data.ByteString.Internal


data TAPDesc
data Frame

type DevMAC = [Word8]

mkDevMAC :: [Word8] -> [Word8]
mkDevMAC m | length m == 6 = m
mkDevMAC _ = undefined 

newtype TAP = TAP (Ptr TAPDesc) deriving Show
type TUN = TAP

maxPktSize :: Int
maxPktSize = 1560

openTAP, openTUN :: String -> IO TAP
openTAP name = openDev name 2; openTUN name = openDev name 1

openDev :: String -> CInt -> IO TAP
openDev name mode = do
  desc <- init_tap_ffi
  withCString name $ \s -> open_tap_ffi desc s mode
  pure $ TAP desc

closeTAP, closeTUN :: TAP -> IO CInt
closeTUN = closeTAP
closeTAP (TAP p) = close_tap_ffi p

bringUp :: TAP -> IO CInt
bringUp (TAP p) = bring_up_tap_ffi p

setMTU :: TAP -> Int -> IO CInt
setMTU (TAP p) m = set_mtu_ffi p $ fromIntegral m

setIP :: TAP -> Word32 -> IO CInt
setIP (TAP p) a = set_ip_ffi p $ fromIntegral a

setMask :: TAP -> Word32 -> IO CInt
setMask (TAP p) m = set_mask_ffi p $ fromIntegral m

getMAC :: TAP -> IO DevMAC
getMAC (TAP p) = allocaArray 6 $ \m -> do
  get_mac_ffi p m
  mkDevMAC . map fromIntegral <$> peekArray 6 m

readTAP, readTUN :: TAP -> IO ByteString
readTUN = readTAP
readTAP t = readTAPwithOffset t 0

readTAPWithOffset, readTAPwithOffset :: TAP -> Int -> IO ByteString
readTAPwithOffset = readTAPWithOffset
readTAPWithOffset (TAP t) off = do
  fptr_buf <- mallocForeignPtrBytes $ maxPktSize + off
  fd <- tap_get_fd_ffi t
  len <- withForeignPtr fptr_buf $ \ptr_buf -> do
    memset ptr_buf 0x0 (fromIntegral off)
    go fd ptr_buf
  pure $ fromForeignPtr fptr_buf 0 (fromIntegral len + off)
  where 
  go fd ptr_buf = do
    threadWaitRead $ fromIntegral fd
    blen <- read_ffi fd (plusPtr ptr_buf off) (fromIntegral maxPktSize)
    if blen > 0
      then pure blen
      else go fd ptr_buf

writeTAP, writeTUN :: TAP -> ByteString -> IO Int
writeTUN = writeTAP
writeTAP (TAP t) pkt = case toForeignPtr pkt of
  (fptr_buf, off, len) -> withForeignPtr fptr_buf $ \ptr_buf -> do
    fd <- tap_get_fd_ffi t
    fromIntegral <$> write_ffi fd (plusPtr ptr_buf off) (fromIntegral len)


foreign import CALLCONV "help.h init_tap" init_tap_ffi :: IO (Ptr TAPDesc)

foreign import CALLCONV "help.h finish_tap" finish_tap_ffi :: Ptr TAPDesc -> IO CInt

foreign import CALLCONV unsafe "help.h tap_get_fd" tap_get_fd_ffi :: Ptr TAPDesc -> IO CInt

foreign import CALLCONV "help.h open_tap" open_tap_ffi :: Ptr TAPDesc -> CString -> CInt -> IO CInt

foreign import CALLCONV "help.h close_tap" close_tap_ffi :: Ptr TAPDesc -> IO CInt

foreign import CALLCONV "help.h bring_up_tap" bring_up_tap_ffi :: Ptr TAPDesc -> IO CInt

foreign import CALLCONV "help.h set_mtu" set_mtu_ffi :: Ptr TAPDesc -> CUInt -> IO CInt

foreign import CALLCONV "help.h set_ip" set_ip_ffi :: Ptr TAPDesc -> CUInt -> IO CInt

foreign import CALLCONV "help.h set_mask" set_mask_ffi :: Ptr TAPDesc -> CUInt -> IO CInt

foreign import CALLCONV "help.h get_mac" get_mac_ffi :: Ptr TAPDesc -> Ptr CUChar -> IO CInt

foreign import CALLCONV "read" read_ffi :: CInt -> Ptr Word8 -> CSize -> IO CInt

foreign import CALLCONV "write" write_ffi :: CInt -> Ptr Word8 -> CInt -> IO CInt
