{-# LANGUAGE OverloadedStrings, PatternGuards #-}

module Network.Kallisti.Api where

import Control.Concurrent
import Data.Aeson
import Data.Aeson.Encode.Pretty
import qualified Data.ByteString as Strict
import qualified Data.ByteString.Char8 as String
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Lazy as Lazy
import Data.ByteString.Builder
import Data.Foldable
import Data.List (partition)
import Data.Monoid ((<>))
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Text (Text)
import Data.Text.Encoding
import qualified Data.Text as Text
import Network.HTTP.Types
import Network.Kallisti.Builder
import Network.Kallisti.Config
import Network.Kallisti.CryptoBox
import Network.Kallisti.TAI
import Network.Wai


api
  :: MVar TAI           -- last api request
  -> Shared Key         -- shared secret
  -> MVar ()            -- global exit operator
  -> Map (Public Key) (Peer -> IO ())  -- restart actions
  -> FilePath           -- config file path
  -> Application
api u k exit control cfg request respond = do
  result <- validate u k request
  respond =<< case (result, requestMethod request, pathInfo request) of
    (Just    _,    "GET", "peer" : ident : _) -> authenticate k =<< get ident cfg
    (Just body,    "PUT", "peer" : ident : _) -> authenticate k =<< put ident control cfg body
    (Just body,  "PATCH", "peer" : ident : _) -> authenticate k =<< patch ident control cfg body
    (Just    _, "DELETE", "peer" : ident : _) -> authenticate k =<< delete ident cfg
    (Just    _,    "GET", "peer" : _) -> authenticate k =<< getAll cfg
    (Just body,   "POST", "peer" : _) -> authenticate k =<< post cfg body
    (Just body,   "POST", "echo" : _) -> authenticate k (status200, body) 
    (Just    _,  "PATCH", []) -> authenticate k =<< terminate exit
    (Nothing, _, _) -> pure $ responseBuilder status401 [] mempty
    _ -> pure $ responseBuilder status404 [] mempty

public :: Text -> Public Key
public = Public . fst . Base16.decode . encodeUtf8 . Text.take 64

terminate :: MVar () -> IO (Status, Message)
terminate exit = do
  forkIO $ threadDelay 1000000 >> putMVar exit ()
  pure (status200, mempty)

patch :: Text -> Map (Public Key) (Peer -> IO ()) -> FilePath -> Message -> IO (Status, Message)
patch ident control cfg _ = do
  file <- Lazy.fromStrict <$> Strict.readFile cfg
  case eitherDecode file of
    Right config
      | peer:_ <- filter (\p -> public ident == publicKey p) $ peers config
      -> do
        for_ (public ident `Map.lookup` control) $ \restart -> restart peer
        pure (status200, Lazy.toStrict $ encode True)
    Right _ -> pure (status400, mempty)
    Left  e -> pure (status500, String.pack $ show e)

put :: Text -> Map (Public Key) (Peer -> IO ()) -> FilePath -> Message -> IO (Status, Message)
put ident control cfg body = do
  file <- Lazy.fromStrict <$> Strict.readFile cfg
  case eitherDecode file of
    Right config
      | Just peer <- decode $ Lazy.fromStrict body
      , (_:_, rest) <- partition (\p -> public ident == publicKey p) $ peers config
      -> do
        Lazy.writeFile cfg $ encodePretty config { peers = peer : rest }
        for_ (public ident `Map.lookup` control) $ \restart -> restart peer
        pure (status200, Lazy.toStrict $ encode True)
    Right _ -> pure (status400, mempty)
    Left  e -> pure (status500, String.pack $ show e)

post :: FilePath -> Message -> IO (Status, Message)
post cfg body = do
  file <- Lazy.fromStrict <$> Strict.readFile cfg
  case eitherDecode file of
    Right config
      | Just peer <- decode $ Lazy.fromStrict body
      , pk <- publicKey peer
      , ([], rest) <- partition (\p -> pk == publicKey p) $ peers config
      -> do
        Lazy.writeFile cfg $ encodePretty config { peers = peer : rest }
        pure (status201, Lazy.toStrict $ encode True)
    Right _ -> pure (status400, mempty)
    Left  e -> pure (status500, String.pack $ show e)

delete :: Text -> FilePath -> IO (Status, Message)
delete ident cfg = do
  file <- Lazy.fromStrict <$> Strict.readFile cfg
  case eitherDecode file of
    Right config
      | (_:_, rest) <- partition (\p -> public ident == publicKey p) $ peers config
      -> do
        Lazy.writeFile cfg $ encodePretty config { peers = rest }
        pure (status200, mempty)
    Right _ -> pure (status400, mempty)
    Left  e -> pure (status500, String.pack $ show e)

get :: Text -> FilePath -> IO (Status, Message)
get ident cfg = do
  file <- Lazy.readFile cfg
  case eitherDecode file of
    Right config
      | peer:_ <- filter (\p -> public ident == publicKey p) $ peers config
      -> pure (status200, Lazy.toStrict $ encode peer)
    Right _ -> pure (status404, mempty)
    Left  e -> pure (status500, String.pack $ show e)

getAll :: FilePath -> IO (Status, Message)
getAll cfg = do
  file <- Lazy.readFile cfg
  case eitherDecode file of
    Right config -> pure (status200, Lazy.toStrict . encode $ peers config)
    Left e -> pure (status500, String.pack $ show e)

-- | HTTP method, path and body are authenticated
--  
--  maximum body size: 512, maximum path segments: 4
--
--  GET /echo\n
--  http body..
--
validate :: MVar TAI -> Shared Key -> Request -> IO (Maybe Message)
validate u k request
  | Just t' <- taiFromByteString . fst . Base16.decode . Strict.take 24 <$> lookup "X-Timestamp" headers
  = do
    t <- readMVar u
    if t < t'
      then do
        message <- Lazy.take 496 <$> lazyRequestBody request
        result <- cryptoBoxOpenUnsafe k (nonce t') $
          fromBuilder 512 $ byteString (zeroBytes 16) <> lazyByteString message
        case String.drop 32 <$> result of
          Just string
            | (method, xs) <- String.break (== ' ') string
            , requestMethod request == method
            , (path, body) <- String.break (=='\n') xs
            , pathInfo request == [x | x <- Text.split (=='/') $ decodeLatin1 path, not $ Text.null x]
            -> Just body <$ swapMVar u t'
          _ -> pure Nothing
      else pure Nothing
  where headers = requestHeaders request
validate _ _ _ = pure Nothing

authenticate :: Shared Key -> (Status, Message) -> IO Response
authenticate k (status, body) = do
  now <- getTAIAttoOffset =<< randomNum
  let Authenticated result = cryptoBox k now body
  pure $ responseBuilder status [("X-Nonce", Base16.encode $ taiBytes now)] $ byteString result

