{-# LANGUAGE ForeignFunctionInterface, CPP #-}

module Network.Kallisti.CTools where

import Foreign.C.Types
import Foreign.C.String
import Foreign.Ptr


dropPrivileges :: Maybe String -> IO ()
dropPrivileges a = do
  success <- setUidGid a
  if not success
    then fail $ "unknown account set in \"setuid\" option: "++ maybe "" id a
    else () <$ changeRoot "."

setUidGid :: Maybe String -> IO Bool
setUidGid (Just a) = (== 0) <$> withCString a setuidgid
setUidGid _ = pure True

changeRoot :: String -> IO Bool
changeRoot p = (== 0) <$> withCString p changeroot

foreign import CALLCONV "help.h setuidgid" setuidgid :: Ptr CChar -> IO CInt
foreign import CALLCONV "help.h changeroot" changeroot :: Ptr CChar -> IO CInt

