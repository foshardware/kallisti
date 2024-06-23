{-# LANGUAGE PatternGuards #-}

module Network.Kallisti.Builder where

import Data.Word
import Data.ByteString
import qualified Data.ByteString.Lazy as Lazy
import Data.ByteString.Builder
import Data.ByteString.Builder.Extra


fromWord64 :: Word64 -> ByteString
fromWord64 n = fromBuilder 24 $ word64BE 0 <> word64BE 0 <> word64BE n

fromBuilder :: Int -> Builder -> ByteString
fromBuilder n b
  | x:_ <- Lazy.toChunks $ toLazyByteStringWith (untrimmedStrategy n smallChunkSize) mempty b
  = x
fromBuilder _ _ = mempty

