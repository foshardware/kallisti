{-# LANGUAGE ForeignFunctionInterface, CPP, TupleSections #-}

module Network.Kallisti.Socket where

import Control.Concurrent (threadWaitRead)
import Data.ByteString.Internal
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable
import Network.Socket
import Network.Socket.Internal


recvWithOffset :: Socket -> Int -> Int -> IO ByteString
recvWithOffset s l o = fst <$> recvFromWithOffset s l o

recvFromWithOffset :: Socket -> Int -> Int -> IO (ByteString, SockAddr)
recvFromWithOffset (MkSocket fd family _ _ _) len off =
  withNewSockAddr family $ \ptr_addr sz -> alloca $ \ptr_len -> do
    poke ptr_len (fromIntegral sz)
    fptr_buf <- mallocForeignPtrBytes (len + off)
    (blen, addr) <- withForeignPtr fptr_buf $ \ptr_buf -> do
      memset ptr_buf 0x0 (fromIntegral off)
      go ptr_buf ptr_addr ptr_len
    pure (fromForeignPtr fptr_buf 0 (fromIntegral blen + off), addr)
    where
    go ptr_buf = \ptr_addr ptr_len -> do
      threadWaitRead (fromIntegral fd)
      blen <- recvfrom fd (plusPtr ptr_buf off) (fromIntegral len) 0 ptr_addr ptr_len
      if blen > 0
        then (blen, ) <$> peekSockAddr ptr_addr
        else go ptr_buf ptr_addr ptr_len

foreign import CALLCONV "recvfrom" recvfrom
  :: CInt -> Ptr a -> CSize -> CInt -> Ptr SockAddr -> Ptr CInt -> IO CInt
