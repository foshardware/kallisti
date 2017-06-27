{-# LANGUAGE ForeignFunctionInterface, EmptyDataDecls, CPP #-}

module Network.Kallisti.CryptoBox where

import Data.Word
import Foreign.C.Types
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Storable
import Foreign.Marshal.Alloc
import Data.ByteString.Char8
import Data.ByteString.Base16
import Data.ByteString.Internal
import qualified Data.ByteString as BS
import Network.Kallisti.TAI
import System.IO.Unsafe


type Key = ByteString

newtype Secret a = Secret a
newtype Public a = Public a deriving (Eq, Ord)

newtype Shared a = Shared a 

type Keypair = (Public Key, Secret Key)


newtype Authenticated a = Authenticated a
instance Functor Authenticated where fmap f (Authenticated a) = Authenticated (f a)

class Nonce a where
  nonce :: a -> ByteString

instance Nonce ByteString where
  nonce n | BS.length n < 24 = error "CryptoBox: nonce length < 24 bytes"
  nonce n = n
  {-# SPECIALIZE INLINE nonce :: ByteString -> ByteString #-}

instance Nonce TAI where
  nonce (TAI n) = fromForeignPtr n 0 24
  {-# SPECIALIZE INLINE nonce :: TAI -> ByteString #-}

type Message = ByteString
type Ciphertext = ByteString

keyFromHex :: String -> Key
keyFromHex = fst . decode . pack

hexFromKey :: Key -> String
hexFromKey = unpack . encode

cryptoBoxInit :: IO Bool
cryptoBoxInit = (0 ==) <$> sodium_init

cryptoBoxKeypair :: IO Keypair
cryptoBoxKeypair = do
  p <- mallocForeignPtrBytes 32
  s <- mallocForeignPtrBytes 32
  withForeignPtr (castForeignPtr p) $ \p' ->
   withForeignPtr (castForeignPtr s) $ \s' ->
     crypto_box_keypair p' s'
  castFunPtr zeroes32 `addForeignPtrFinalizer` s
  pure (Public $ fromForeignPtr p 0 32, Secret $ fromForeignPtr s 0 32)

cryptoBoxScalarMult :: Secret Key -> Public Key
cryptoBoxScalarMult (Secret k) = unsafePerformIO $ do
  p <- mallocForeignPtrBytes 32
  let (s, so, _) = toForeignPtr k
  withForeignPtr (castForeignPtr p) $ \p' ->
   withForeignPtr (castForeignPtr s) $ \s' ->
     crypto_scalarmult_base p' $ plusPtr s' so
  pure . Public $ fromForeignPtr p 0 32

cryptoBoxBeforeNM :: Public Key -> Secret Key -> Shared Key
cryptoBoxBeforeNM (Public pk) (Secret sk) = unsafePerformIO $ do
  k <- mallocForeignPtrBytes 32
  let (p, po, _) = toForeignPtr pk
      (s, so, _) = toForeignPtr sk
  withForeignPtr k $ \k' ->
   withForeignPtr p $ \p' ->
    withForeignPtr s $ \s' ->
     crypto_box_beforenm (castPtr k') (plusPtr p' po) (plusPtr s' so)
  castFunPtr zeroes32 `addForeignPtrFinalizer` k
  pure . Shared $ fromForeignPtr k 0 32

cryptoBox :: Nonce n => Shared Key -> n -> Message -> Authenticated Ciphertext
cryptoBox key i = fmap (BS.drop 16)
  . unsafePerformIO
  . cryptoBoxUnsafe key (nonce i)
  . BS.append (zeroBytes 32)
{-# SPECIALIZE INLINE cryptoBox :: Shared Key -> TAI -> ByteString -> Authenticated ByteString #-}

-- | Referential transparency is only given for messages that start with 32 zero bytes
-- there is also no check for size
cryptoBoxUnsafe :: Shared Key -> ByteString -> ByteString -> IO (Authenticated ByteString)
cryptoBoxUnsafe (Shared key) i msg = do
  case (toForeignPtr msg, toForeignPtr i, toForeignPtr key) of
    ((m, mo, ml), (n, no,  _), (k, ko,  _)) -> do
      c <- mallocForeignPtrBytes ml
      withForeignPtr c $ \c' ->
       withForeignPtr k $ \k' ->
        withForeignPtr n $ \n' ->
         withForeignPtr m $ \m' -> do
          memset (plusPtr m' mo) 0x0 32
          crypto_box_afternm
            (castPtr c') (plusPtr m' mo) (fromIntegral ml) (plusPtr n' no) (plusPtr k' ko)
      pure . Authenticated $ fromForeignPtr c 0 ml
{-# INLINE cryptoBoxUnsafe #-}

cryptoBoxOpen :: Nonce n => Shared Key -> n -> Message -> Maybe Message
cryptoBoxOpen key i = fmap (BS.drop 32)
  . unsafePerformIO
  . cryptoBoxOpenUnsafe key (nonce i)
  . BS.append (zeroBytes 16)
{-# SPECIALIZE INLINE cryptoBoxOpen :: Shared Key -> TAI -> ByteString -> Maybe ByteString #-}

-- | Referential transparency is only given for ciphertexts that start with 16 zero bytes
-- there is also no check for size
cryptoBoxOpenUnsafe :: Shared Key -> ByteString -> ByteString -> IO (Maybe ByteString)
cryptoBoxOpenUnsafe (Shared key) i text =
  case (toForeignPtr text, toForeignPtr i, toForeignPtr key) of
    ((c, co, cl), (n, no,  _), (k, ko,  _)) -> do
      m <- mallocForeignPtrBytes cl
      ret <- withForeignPtr c $ \c' ->
       withForeignPtr k $ \k' ->
        withForeignPtr n $ \n' ->
         withForeignPtr m $ \m' -> do
          memset (plusPtr c' co) 0x0 16
          crypto_box_open_afternm
            (castPtr m') (plusPtr c' co) (fromIntegral cl) (plusPtr n' no) (plusPtr k' ko)
      case ret of 
        0 -> pure . Just $ fromForeignPtr m 0 cl
        _ -> Nothing <$ finalizeForeignPtr m
{-# INLINE cryptoBoxOpenUnsafe #-}

randomBytes :: Int -> IO ByteString
randomBytes n = do
  r <- mallocForeignPtrBytes n
  withForeignPtr r $ \r' -> randombytes (castPtr r') (fromIntegral n)
  pure $ fromForeignPtr r 0 n
{-# INLINABLE randomBytes #-}

randomNum :: (Num a, Storable a) => IO a
randomNum = doAlloc 0 $ \size rnd -> do
  castPtr rnd `randombytes` fromIntegral size
  peek rnd
  where
    doAlloc :: Storable a => a -> (Int -> Ptr a -> IO a) -> IO a
    doAlloc x f = allocaBytes (sizeOf x) (f (sizeOf x))
{-# SPECIALIZE INLINE randomNum :: IO Word32 #-}
{-# SPECIALIZE INLINE randomNum :: IO Word64 #-}

zeroBytes :: Int -> ByteString
zeroBytes n = BS.replicate n 0x0
{-# INLINABLE zeroBytes #-}

data Bytes

foreign import CALLCONV "help.h &zeroes32" zeroes32 :: FunPtr (Ptr Bytes -> IO ())


foreign import CALLCONV "sodium_init" sodium_init :: IO CInt

foreign import CALLCONV "crypto_box_keypair" crypto_box_keypair
  :: Ptr Bytes -> Ptr Bytes -> IO ()

foreign import CALLCONV "crypto_scalarmult_base" crypto_scalarmult_base
  :: Ptr Bytes -> Ptr Bytes -> IO ()

foreign import CALLCONV "crypto_box_beforenm" crypto_box_beforenm
  :: Ptr Bytes -> Ptr Bytes -> Ptr Bytes -> IO ()

foreign import CALLCONV "crypto_box_afternm" crypto_box_afternm
  :: Ptr Bytes -> Ptr Bytes -> CULLong -> Ptr Bytes -> Ptr Bytes -> IO ()

foreign import CALLCONV "crypto_box_open_afternm" crypto_box_open_afternm
  :: Ptr Bytes -> Ptr Bytes -> CULLong -> Ptr Bytes -> Ptr Bytes -> IO CInt

foreign import CALLCONV "randombytes" randombytes
  :: Ptr Bytes -> CULLong -> IO ()


data Forward a = Forward !Word64 a a

instance Eq (Forward a) where
  Forward t _ _ == Forward u _ _ = t == u

instance Ord (Forward a) where
  Forward t _ _ `compare` Forward u _ _ = t `compare` u

fsBoxUnsafe :: Forward (Shared Key) -> ByteString -> ByteString -> IO (Authenticated ByteString)
fsBoxUnsafe (Forward _ a _) i m = cryptoBoxUnsafe a i m

fsBoxPeriodUnsafe
  :: Word64 -> Forward (Shared Key) -> ByteString -> ByteString -> IO (Authenticated ByteString)
fsBoxPeriodUnsafe t (Forward u a _) i m | t > u = cryptoBoxUnsafe a i m
fsBoxPeriodUnsafe _ (Forward _ _ a) i m = cryptoBoxUnsafe a i m

fsBoxOpenUnsafe :: Forward (Shared Key) -> ByteString -> ByteString -> IO (Maybe ByteString)
fsBoxOpenUnsafe (Forward _ a b) i c = do
  result <- cryptoBoxOpenUnsafe a i c
  case result of
    Nothing -> cryptoBoxOpenUnsafe b i c
    success -> pure success

fsBoxOpenPeriodUnsafe
  :: Word64 -> Forward (Shared Key) -> ByteString -> ByteString -> IO (Maybe ByteString)
fsBoxOpenPeriodUnsafe t (Forward u a _) i c | t > u = cryptoBoxOpenUnsafe a i c
fsBoxOpenPeriodUnsafe _ (Forward _ _ a) i c = cryptoBoxOpenUnsafe a i c

commitForward :: Word64 -> a -> Forward a -> Forward a
commitForward u _ f@(Forward t _ _) | u <= t = f
commitForward u a (Forward _ b _) = Forward u a b

initForwardSecret :: Word64 -> IO (Forward (Shared Key))
initForwardSecret t = do
  (_, sk) <- cryptoBoxKeypair
  (pk, _) <- cryptoBoxKeypair
  let a = cryptoBoxBeforeNM pk sk in pure $ Forward t a a

