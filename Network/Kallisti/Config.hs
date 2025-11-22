{-# LANGUAGE OverloadedStrings #-}

module Network.Kallisti.Config where

import Control.Monad
import Data.Aeson hiding (Key)
import Data.Char
import Network.Kallisti.CryptoBox
import Network.Kallisti.Protocol


data Config = Config
  { peers :: [Peer]
  , secretKey :: Secret Key
  , setuid :: Maybe String
  , localWebPort :: Int
  , localWebTLS :: Bool
  }

data Peer = Peer
  { interface :: String
  , tapMode :: String
  , protocolIdent :: String
  , debug :: Bool
  , remoteAddr :: Maybe String
  , remotePort :: Int
  , remoteWebPort :: Int
  , localAddr :: Maybe String
  , localPort :: Int
  , publicKey :: Public Key
  , mtu :: Int
  }

protocol :: Peer -> Protocol
protocol = read . protocolIdent

instance FromJSON Config where
  parseJSON (Object v) = Config
    <$> v .:? "peers" .!= []
    <*> (Secret . keyFromHex <$> v .: "secretKey")
    <*> v .:? "setuid"
    <*> v .:? "localWebPort" .!= 7000
    <*> v .:? "localWebTLS" .!= False
  parseJSON _ = mzero

instance ToJSON Config where
  toJSON c = object
    [ "peers" .= peers c
    , "secretKey" .= hexFromKey sk
    , "setuid" .= setuid c
    , "localWebPort" .= localWebPort c
    , "localWebTLS" .= localWebTLS c
    ]
    where Secret sk = secretKey c

instance FromJSON Peer where
  parseJSON (Object v) = Peer
    <$> v .:? "interface" .!= "kallisti"
    <*> (map toLower <$> v .:? "tapMode" .!= "tun")
    <*> (map toLower <$> v .:? "protocol" .!= "nacltai")
    <*> v .:? "debug" .!= False
    <*> v .:? "remoteAddress"
    <*> v .:? "remotePort" .!= 7000
    <*> v .:? "remoteWebPort" .!= 7000
    <*> v .:? "localAddress"
    <*> v .:? "localPort" .!= 7000
    <*> (Public . keyFromHex <$> v .: "publicKey")
    <*> v .:? "MTU" .!= 1500
  parseJSON _ = mzero

instance ToJSON Peer where
  toJSON p = object
    [ "interface" .= interface p
    , "tapMode" .= tapMode p
    , "protocol" .= protocolIdent p
    , "debug" .= debug p
    , "remoteAddress" .= remoteAddr p
    , "remotePort" .= remotePort p
    , "remoteWebPort" .= remoteWebPort p
    , "localAddress" .= localAddr p
    , "localPort" .= localPort p
    , "publicKey" .= hexFromKey pk
    , "MTU" .= mtu p
    ]
    where Public pk = publicKey p

