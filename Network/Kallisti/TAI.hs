{-# LANGUAGE ForeignFunctionInterface, CPP #-}

module Network.Kallisti.TAI where

import Data.ByteString.Internal
import Data.Word
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Storable
import Foreign.C.Types


newtype TAI = TAI (ForeignPtr Word8)

instance Eq TAI where
  t == u = taiAttoIndex t == taiAttoIndex u && taiSeconds t == taiSeconds u

instance Ord TAI where
 t `compare` u | taiSeconds t == taiSeconds u = taiAttoIndex t `compare` taiAttoIndex u
 t `compare` u = taiSeconds t `compare` taiSeconds u

instance Show TAI where
  show t = show (taiSeconds t) ++"."++ show (taiNanoseconds t) ++"s"

instance Storable TAI where
  sizeOf = const 16
  alignment = const 8
  poke p (TAI n) = withForeignPtr n $ \n' -> memcpy (castPtr p) n' 16
  peek p = do
    t <- mallocForeignPtrBytes 24
    withForeignPtr t $ \t' -> TAI t
      <$ memset (plusPtr (castPtr t') 16) 0x0 8
      <* memcpy t' (castPtr p) 16

getTAI :: IO TAI
getTAI = getTAIAttoOffset 0

getTAICoarse :: IO TAI
getTAICoarse = getTAICoarseAttoOffset 0

taiBytes :: TAI -> ByteString
taiBytes (TAI t) = fromForeignPtr t 0 16

unsafeRO :: IO a -> a
unsafeRO = accursedUnutterablePerformIO

taiFromByteString :: ByteString -> TAI
taiFromByteString bs = case toForeignPtr bs of
  (_, _, l) | l < 16 -> error "taiFromByteString: length"
  (p, o, _) -> unsafeRO $ withForeignPtr p $ \p' -> peek $ plusPtr p' o

-- 32 bits seconds + 32 bits nanoseconds 
taiIndex :: TAI -> Word64
taiIndex (TAI u) = unsafeRO . withForeignPtr u $ peek . castPtr . (`plusPtr` 4)

taiSeconds :: TAI -> Word64
taiSeconds (TAI u) = unsafeRO . withForeignPtr u $ peek . castPtr . (`plusPtr` 8)

taiNanoseconds :: TAI -> Word32
taiNanoseconds (TAI u) = unsafeRO . withForeignPtr u $ peek . castPtr . (`plusPtr` 4)

taiAttoseconds :: TAI -> Word32
taiAttoseconds (TAI u) = unsafeRO . withForeignPtr u $ peek . castPtr

-- 32 bits nanoseconds + 32 bits attoseconds 
taiAttoIndex :: TAI -> Word64
taiAttoIndex (TAI u) = unsafeRO . withForeignPtr u $ peek . castPtr

getTAIAttoOffset :: Word32 -> IO TAI
getTAIAttoOffset n = do
  ptr <- mallocForeignPtrBytes 24
  withForeignPtr ptr $ \t -> taia_now t $ fromIntegral n
  pure . TAI $ castForeignPtr ptr

getTAICoarseAttoOffset :: Word32 -> IO TAI
getTAICoarseAttoOffset n = do
  ptr <- mallocForeignPtrBytes 24
  withForeignPtr ptr $ \t -> taia_now_coarse t $ fromIntegral n
  pure . TAI $ castForeignPtr ptr

foreign import CALLCONV unsafe "help.h taia_now_offset" taia_now
  :: Ptr Word64 -> CULong -> IO ()
foreign import CALLCONV unsafe "help.h taia_now_coarse_offset" taia_now_coarse
  :: Ptr Word64 -> CULong -> IO ()

