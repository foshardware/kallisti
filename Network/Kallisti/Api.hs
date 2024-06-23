{-# LANGUAGE OverloadedStrings, PatternGuards #-}

module Network.Kallisti.Api where

import Network.HTTP.Types
import Network.Wai


api :: Application
api _ respond = respond $ responseBuilder status401 [] mempty

