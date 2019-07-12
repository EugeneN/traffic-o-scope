-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2019 Bin Jin. All Rights Reserved.
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DeriveAnyClass     #-}
{-# LANGUAGE DeriveGeneric      #-}
{-# LANGUAGE FlexibleInstances      #-}

module HProx
  ( ProxySettings(..)
  , httpProxy
  , pacProvider
  , httpGetProxy
  , httpConnectProxy
  , reverseProxy
  , forceSSL
  , dumbApp
  , adminApp
  , BlacklistItem(..)
  ) where

import qualified GHC.Generics as GHC
import           Control.Applicative        ((<|>))
import           Control.Concurrent.Async   (concurrently)
import           Control.Exception          (SomeException, try)
import           Control.Monad              (unless, void, when, forM_)
import           Control.Monad.IO.Class     (liftIO)
import           Data.Aeson
import           Data.Aeson.Types
import qualified Data.Binary.Builder        as BB
import qualified Data.ByteString            as BS
import           Data.ByteString.Base64     (decodeLenient)
import qualified Data.ByteString.Char8      as BS8
import qualified Data.ByteString.Lazy.Char8 as LBS8
import qualified Data.CaseInsensitive       as CI
import           Data.CaseInsensitive       (CI(..))
import qualified Data.Conduit.Network       as CN
import           Data.Maybe                 (fromJust, fromMaybe, isJust,
                                             isNothing, listToMaybe)
import qualified Data.Text                  as T   
import qualified Data.Text.Encoding         as TE 
import           Data.Time.Clock    
import           Database.SQLite.Simple     
import           Database.SQLite.Simple.FromRow()       
import qualified Network.HTTP.Client        as HC
import           Network.HTTP.ReverseProxy  (ProxyDest (..), SetIpHeader (..),
                                             WaiProxyResponse (..),
                                             defaultWaiProxySettings,
                                             waiProxyToSettings, wpsSetIpHeader,
                                             wpsUpgradeToRaw)
import qualified Network.HTTP.Types         as HT
import qualified Network.HTTP.Types.Header  as HT
import           Network.Wai.Internal       (getRequestBodyChunk)
import           Network.Wai.Util           (queryLookup)

import           Data.Conduit
import           Network.Wai
import           Network.Wai.Internal        (Request(..))

import qualified Text.Blaze.Html5            as H
import qualified Text.Blaze.Html5.Attributes as A
import           Text.Blaze.Html.Renderer.Pretty (renderHtml)
import qualified Data.ByteString.Lazy as LZ

data ProxySettings = ProxySettings
  { proxyAuth  :: Maybe (BS.ByteString -> Bool)
  , passPrompt :: Maybe BS.ByteString
  , wsRemote   :: Maybe BS.ByteString
  , revRemote  :: Maybe BS.ByteString
  }

data BlacklistItem = BlacklistItem Int T.Text deriving (Show)

instance FromRow BlacklistItem where
  fromRow = BlacklistItem <$> field <*> field

instance ToRow BlacklistItem where
  toRow (BlacklistItem id_ dn) = toRow (id_, dn)

data BlockedItem = BlockedItem UTCTime T.Text T.Text deriving (Show)

instance FromRow BlockedItem where
  fromRow = BlockedItem <$> field <*> field <*> field

instance ToRow BlockedItem where
  toRow (BlockedItem dt dn rq) = toRow (dt, dn, rq)

data AllowedItem = AllowedItem UTCTime T.Text deriving (Show)

instance FromRow AllowedItem where
  fromRow = AllowedItem <$> field <*> field

instance ToRow AllowedItem where
  toRow (AllowedItem dt dn) = toRow (dt, dn)

newtype Count = Count { uncount :: Integer}
instance FromRow Count where
  fromRow = Count <$> field

data SavedRequest = 
  SavedRequest
    { s_requestMethod          :: HT.Method
    , s_rawPathInfo            :: BS8.ByteString
    , s_rawQueryString         :: BS8.ByteString
    , s_requestHeaders         :: HT.RequestHeaders
    , s_requestBody            :: BS8.ByteString
    , s_requestHeaderHost      :: Maybe BS8.ByteString
    , s_requestHeaderRange     :: Maybe BS8.ByteString
    , s_requestHeaderReferer   :: Maybe BS8.ByteString
    , s_requestHeaderUserAgent :: Maybe BS8.ByteString
    } deriving (GHC.Generic, Show, FromJSON, ToJSON)

instance (CI.FoldCase a, FromJSON a) => FromJSON (CI a) where
  parseJSON (Object o) = CI.mk <$> (o .: "original")
  parseJSON v          = typeMismatch "CI a" v

instance (CI.FoldCase a, ToJSON a) => ToJSON (CI a) where
  toJSON x = object [ "original"   .= CI.original x ]

instance FromJSON BS8.ByteString where
  parseJSON v = BS8.pack . T.unpack <$> (parseJSON v :: Parser T.Text)

instance ToJSON BS8.ByteString where
  toJSON = toJSON . T.pack . BS8.unpack

adminApp :: Connection -> Application
adminApp conn req respond = do
  resp <- case pathInfo req of
    [] -> do
      blacklist <- query_ conn "SELECT count(*) from blacklist" :: IO [Count]
      blocked   <- query_ conn "SELECT count(*) from blocked"   :: IO [Count]
      allowed   <- query_ conn "SELECT count(*) from allowed"   :: IO [Count]

      pure $ respOk $ dashboardH blacklist blocked allowed

    ["blacklist"] -> do
      r <- query_ conn "SELECT * from blacklist" :: IO [BlacklistItem]
      pure $ respOk $ blacklistH r

    ["blocked"]   -> do
      r <- query_ conn "SELECT * from blocked" :: IO [BlockedItem]
      pure $ respOk $ blockedH r

    ["allowed"]   -> do
      r <- query_ conn "SELECT * from allowed" :: IO [AllowedItem]
      pure $ respOk $ allowedH r
    
    ["itworks"]   -> do
      pure $ respOk itWorks
    
    ["cmd"]   -> do
      body <- strictRequestBody req
      let as   = LBS8.split '&' body
          bs   = fmap (listToTuple . LBS8.split '=') as
          cmd  = fmap snd $ listToMaybe . filter ((==) "cmd" . fst) $ bs
          val  = fmap (TE.decodeUtf8 . LZ.toStrict . snd) $ listToMaybe . filter ((==) "val" . fst) $ bs
          qs   = queryString req
          goto = queryLookup ("back" :: BS8.ByteString) qs

      case (cmd, val) of
        (Just cmd', Just val') -> do
          case cmd' of
            "block"   -> do
              putStrLn $ "Got block cmd for " <> T.unpack val'
              execute conn "insert into blacklist (domainname) VALUES (?) " (Only val')
            "unblock" -> do
              putStrLn $ "Got unblock cmd for " <> T.unpack val'
              execute conn "delete from blacklist where domainname = ? " (Only val')
            _         -> putStrLn $ "Got unknown cmd " <> show cmd'

        _ -> putStrLn $ "Can't parse cmd: " <> show (cmd, val)

      pure $ respRedirect $ BS8.pack . T.unpack $ fromMaybe "/" goto

    _xs -> pure $ resp404 $ notFoundH
  
  respond resp 

  where
    listToTuple [x, y] = (x, y)
    listToTuple _ = error "listToTuple"

    notFoundH = 
      let t = "Not found"
          b = H.div $ do
                H.p $ do
                  H.a H.! A.href "/" $ "Back to dashboard"
                H.h1 "Not found"
      in htmlPage t b

    blacklistH r = 
      let t = "Blacklist"
          b = H.div $ do
                H.p $ do
                  H.a H.! A.href "/" $ "Back to dashboard"
                H.h1 "Blacklist"
                H.ul $ 
                  forM_ r $ \(BlacklistItem _ x) -> 
                    H.li $ do
                      H.span $ H.toHtml x
                      H.span $ do
                        H.form 
                          H.! A.action "/cmd?back=/blacklist"
                          H.! A.method "POST" $ do
                            H.input  H.! A.type_ "hidden" H.! A.name "cmd" H.! A.value "unblock"
                            H.input  H.! A.type_ "hidden" H.! A.name "val" H.! A.value (H.toValue x)
                            H.button H.! A.type_ "submit" $ "Unblock"
      in htmlPage t b


    unblockForm back = 
      H.form 
      H.! A.action ("/cmd?back=" <> back)
        H.! A.method "POST" $ do
          H.input  H.! A.type_ "hidden" H.! A.name "cmd" H.! A.value "unblock"
          H.input  H.! A.type_ "text"   H.! A.name "val" H.! A.value ""
          H.button H.! A.type_ "submit" $ "Unblock"

    blockForm back = 
      H.form 
        H.! A.action ("/cmd?back=" <> back)
        H.! A.method "POST" $ do
          H.input  H.! A.type_ "hidden" H.! A.name "cmd" H.! A.value "block"
          H.input  H.! A.type_ "text"   H.! A.name "val" H.! A.value ""
          H.button H.! A.type_ "submit" $ "Block"

    blockedH r = 
      let t = "Blocked"
          b = H.div $ do
                H.p $ do
                  H.a H.! A.href "/" $ "Back to dashboard"
                H.h1 "Blocked"
                H.p $ blockForm   "/blocked"
                H.p $ unblockForm "/blocked"
                H.ul $ 
                  forM_ r $ \(BlockedItem x y _z) -> 
                    H.li $ do
                      H.span $ H.toHtml $ show x
                      H.span $ H.toHtml y
                      H.span $ do
                        H.form 
                          H.! A.action "/cmd?back=/blocked"
                          H.! A.method "POST" $ do
                            H.input  H.! A.type_ "hidden" H.! A.name "cmd" H.! A.value "unblock"
                            H.input  H.! A.type_ "hidden" H.! A.name "val" H.! A.value (H.toValue y)
                            H.button H.! A.type_ "submit" $ "Unblock"

      in htmlPage t b
    
    allowedH r = 
      let t = "Allowed"
          b = H.div $ do
                H.p $ do
                  H.a H.! A.href "/" $ "Back to dashboard"
                H.h1 "Allowed"
                H.p $ blockForm   "/allowed"
                H.p $ unblockForm "/allowed"
                H.ul $ 
                  forM_ r $ \(AllowedItem x y) -> 
                    H.li $ do
                      H.span $ H.toHtml $ show x
                      H.span $ H.toHtml y
                      H.span $ do
                        H.form 
                          H.! A.action "/cmd?back=/allowed"
                          H.! A.method "POST" $ do
                            H.input  H.! A.type_ "hidden" H.! A.name "cmd" H.! A.value "block"
                            H.input  H.! A.type_ "hidden" H.! A.name "val" H.! A.value (H.toValue y)
                            H.button H.! A.type_ "submit" $ "Block"
      in htmlPage t b

    dashboardH blacklist blocked allowed = 
      let t = "Dashboard" 
          b = H.div $ do
                H.h1 "Dashboard"
                H.p $ blockForm   "/"
                H.p $ unblockForm "/"
                H.p $ do
                  "Items in the "
                  H.a H.! A.href "/blacklist" $ "blacklist"
                  ": "
                  H.toHtml $ show . uncount . head $ blacklist
                H.p $ do
                  "Items in "
                  H.a H.! A.href "/blocked" $ "blocked"
                  ": "
                  H.toHtml $ show . uncount . head $ blocked
                H.p $ do
                  "Items in "
                  H.a H.! A.href "/allowed" $ "allowed"
                  ": "
                  H.toHtml $ show . uncount . head $ allowed
      in htmlPage t b


respOk       x   = responseLBS HT.status200 [("Content-Type", "text/html")] $ LBS8.pack . renderHtml $ x
resp404      x   = responseLBS HT.status404 [("Content-Type", "text/html")] $ LBS8.pack . renderHtml $ x
respRedirect uri = responseLBS HT.status301 [("Location", uri)] LZ.empty
  
htmlPage :: H.Html -> H.Html -> H.Html
htmlPage t b = 
  H.docTypeHtml $ do
    H.head $ do
      H.meta H.! A.charset "utf-8"
      H.title t
    H.body H.! A.id "body" $ do
      b

itWorks :: H.Html
itWorks = 
  htmlPage 
    "It works!" $ 
    H.div $ do
      H.h1 "It works!"
      H.p "This is the default web page for this server."
      H.p "The web server software is running but no content has been added, yet."

dumbApp :: Application
dumbApp _req respond =
    respond $ respOk itWorks

httpProxy :: Connection -> ProxySettings -> HC.Manager -> Middleware
httpProxy conn set mgr = pacProvider . httpGetProxy conn set mgr . httpConnectProxy set

forceSSL :: Middleware
forceSSL app req respond
    | isSecure req = app req respond
    | otherwise    = redirectToSSL req respond

redirectToSSL :: Application
redirectToSSL req respond
    | Just host <- requestHeaderHost req = respond $ responseLBS
        HT.status301
        [("Location", "https://" `BS.append` host)]
        ""
    | otherwise                          = respond $ responseLBS
        (HT.mkStatus 426 "Upgrade Required")
        [("Upgrade", "TLS/1.0, HTTP/1.1"), ("Connection", "Upgrade")]
        ""

parseHostPort :: BS.ByteString -> Maybe (BS.ByteString, Int)
parseHostPort hostPort = do
    lastColon <- BS8.elemIndexEnd ':' hostPort
    port <- BS8.readInt (BS.drop (lastColon+1) hostPort) >>= checkPort
    return (BS.take lastColon hostPort, port)
  where
    checkPort (p, bs)
        | BS.null bs && 1 <= p && p <= 65535 = Just p
        | otherwise                          = Nothing

parseHostPortWithDefault :: Int -> BS.ByteString -> (BS.ByteString, Int)
parseHostPortWithDefault defaultPort hostPort =
    fromMaybe (hostPort, defaultPort) $ parseHostPort hostPort

isProxyHeader :: HT.HeaderName -> Bool
isProxyHeader k
    | BS.length bs <= 4     = False
    | c0 /= 112 && c0 /= 80 = False -- 'p'
    | c1 /= 114 && c1 /= 82 = False -- 'r'
    | c2 /= 111 && c2 /= 79 = False -- 'o'
    | c3 /= 120 && c3 /= 88 = False -- 'x'
    | c4 /= 121 && c4 /= 89 = False -- 'y'
    | otherwise             = True
  where
    bs = CI.original k
    idx = BS.index bs

    c0 = idx 0
    c1 = idx 1
    c2 = idx 2
    c3 = idx 3
    c4 = idx 4

isForwardedHeader :: HT.HeaderName -> Bool
isForwardedHeader k
    | BS.length bs <= 10    = False
    | c0 /= 120 && c0 /= 88 = False -- 'x'
    | c1 /= 45              = False -- '-'
    | c2 /= 102 && c2 /= 70 = False -- 'f'
    | c3 /= 111 && c3 /= 79 = False -- 'o'
    | c4 /= 114 && c4 /= 82 = False -- 'r'
    | c5 /= 119 && c5 /= 87 = False -- 'w'
    | c6 /= 97  && c6 /= 65 = False -- 'a'
    | c7 /= 114 && c7 /= 82 = False -- 'r'
    | c8 /= 100 && c8 /= 68 = False -- 'd'
    | c9 /= 101 && c9 /= 69 = False -- 'e'
    | ca /= 100 && ca /= 68 = False -- 'd'
    | otherwise             = True
  where
    bs = CI.original k
    idx = BS.index bs

    c0 = idx 0
    c1 = idx 1
    c2 = idx 2
    c3 = idx 3
    c4 = idx 4
    c5 = idx 5
    c6 = idx 6
    c7 = idx 7
    c8 = idx 8
    c9 = idx 9
    ca = idx 10

isToStripHeader :: HT.HeaderName -> Bool
isToStripHeader h = isProxyHeader h || isForwardedHeader h || h == "X-Real-IP" || h == "X-Scheme"

checkAuth :: ProxySettings -> Request -> Bool
checkAuth pset req
    | isNothing pauth   = True
    | isNothing authRsp = False
    | otherwise         = fromJust pauth decodedRsp
  where
    pauth = proxyAuth pset
    authRsp = lookup HT.hProxyAuthorization (requestHeaders req)

    decodedRsp = decodeLenient $ snd $ BS8.spanEnd (/=' ') $ fromJust authRsp

proxyAuthRequiredResponse :: ProxySettings -> Response
proxyAuthRequiredResponse pset = responseLBS
    HT.status407
    [(HT.hProxyAuthenticate, "Basic realm=\"" `BS.append` prompt `BS.append` "\"")]
    ""
  where
    prompt = fromMaybe "hprox" (passPrompt pset)

accessDeniedResponse :: ProxySettings -> Response
accessDeniedResponse _ = responseLBS
    HT.status412
    []
    (LBS8.unlines [ "Precondition failed o_O" ])

pacProvider :: Middleware
pacProvider fallback req respond
    | pathInfo req == ["get", "hprox.pac"],
      Just host' <- lookup "x-forwarded-host" (requestHeaders req) <|> requestHeaderHost req =
        let issecure = case lookup "x-forwarded-proto" (requestHeaders req) of
                Just proto -> proto == "https"
                Nothing    -> isSecure req
            scheme = if issecure then "HTTPS" else "PROXY"
            defaultPort = if issecure then ":443" else ":80"
            host | 58 `BS.elem` host' = host' -- ':'
                 | otherwise          = host' `BS.append` defaultPort
        in respond $ responseLBS
               HT.status200
               [("Content-Type", "application/x-ns-proxy-autoconfig")] $
               LBS8.unlines [ "function FindProxyForURL(url, host) {"
                            , LBS8.fromChunks ["  return \"", scheme, " ", host, "\";"]
                            , "}"
                            ]
    | otherwise = fallback req respond

reverseProxy :: ProxySettings -> HC.Manager -> Middleware
reverseProxy pset mgr fallback
    | isReverseProxy = waiProxyToSettings (return.proxyResponseFor) settings mgr
    | otherwise      = fallback
  where
    settings = defaultWaiProxySettings { wpsSetIpHeader = SIHNone }

    isReverseProxy = isJust (revRemote pset)
    (revHost, revPort) = parseHostPortWithDefault 80 (fromJust (revRemote pset))

    proxyResponseFor req = WPRModifiedRequest nreq (ProxyDest revHost revPort)
      where
        nreq = req
          { requestHeaders = hdrs
          , requestHeaderHost = Just revHost
          }

        hdrs = (HT.hHost, revHost) : [ (hdn, hdv)
                                     | (hdn, hdv) <- requestHeaders req
                                     , not (isToStripHeader hdn) && hdn /= HT.hHost
                                     ]

httpGetProxy :: Connection -> ProxySettings -> HC.Manager -> Middleware
httpGetProxy conn pset mgr fallback = waiProxyToSettings proxyResponseFor settings mgr
  where
    settings = defaultWaiProxySettings { wpsSetIpHeader = SIHNone }
    proxyResponseFor req = do
      isBlocked <- checkBlocked $ TE.decodeUtf8 . fst <$> hostHeader
      go req isBlocked
        
      where
        isWebsocket = wpsUpgradeToRaw defaultWaiProxySettings req
        redirectWebsocket = isWebsocket && isJust (wsRemote pset)
        (wsHost, wsPort) = parseHostPortWithDefault 80 (fromJust (wsRemote pset))

        notCONNECT = requestMethod req /= "CONNECT"
        rawPath = rawPathInfo req
        rawPathPrefix = "http://"
        defaultPort = 80
        hostHeader = parseHostPortWithDefault defaultPort <$> requestHeaderHost req

        go req' isBlocked
          | isBlocked           = logBlocked req' >> pure (WPRResponse (accessDeniedResponse pset))
          | redirectWebsocket   = logPassed  req' >> pure (WPRProxyDest (ProxyDest wsHost wsPort))
          | not isGetProxy      = logPassed  req' >> pure (WPRApplication fallback)
          | checkAuth pset req' = logPassed  req' >> pure (WPRModifiedRequest nreq (ProxyDest host port))
          | otherwise           = logPassed  req' >> pure (WPRResponse (proxyAuthRequiredResponse pset))

        checkBlocked Nothing = pure True 
        checkBlocked (Just x) = do 
          r <- query conn "SELECT * from blacklist where domainname like ?" (Only x) :: IO [BlacklistItem]
          pure $ case listToMaybe r of
            Nothing -> False
            Just _  -> True

        logBlocked req = do
          now <- getCurrentTime
          print req
          b <- requestBody req
          let sr = SavedRequest
                    { s_requestMethod          = requestMethod req
                    , s_rawPathInfo            = rawPathInfo req
                    , s_rawQueryString         = rawQueryString req
                    , s_requestHeaders         = requestHeaders req
                    , s_requestBody            = b
                    , s_requestHeaderHost      = requestHeaderHost req
                    , s_requestHeaderRange     = requestHeaderRange req
                    , s_requestHeaderReferer   = requestHeaderReferer req
                    , s_requestHeaderUserAgent = requestHeaderUserAgent req
                    } 
              sr' = T.pack . BS8.unpack . LZ.toStrict . encode $ sr
          execute conn "INSERT INTO blocked (datetime, domainname, request) VALUES (?,?,?)" $ (now, (TE.decodeUtf8 $ showHostHeader hostHeader), sr')
          BS8.putStrLn $ "Blocked: " <> showTime now <> " " <> showHostHeader hostHeader

        logPassed _ = do 
          now <- getCurrentTime
          print req
          execute conn "INSERT INTO allowed (datetime, domainname) VALUES (?,?)" $ (now, (TE.decodeUtf8 $ showHostHeader hostHeader))
          BS8.putStrLn $ showTime now <> " " <> showHostHeader hostHeader

        showHostHeader = fromMaybe "Nothing" . fmap fst
        showTime = BS8.pack . show

        isRawPathProxy = rawPathPrefix `BS.isPrefixOf` rawPath
        hasProxyHeader = any (isProxyHeader.fst) (requestHeaders req)
        scheme = lookup "X-Scheme" (requestHeaders req)
        isHTTP2Proxy = HT.httpMajor (httpVersion req) >= 2 && scheme == Just "http" && isSecure req

        isGetProxy = notCONNECT && (isRawPathProxy || isHTTP2Proxy || isJust hostHeader && hasProxyHeader)

        nreq = req
          { rawPathInfo = newRawPath
          , requestHeaders = filter (not.isToStripHeader.fst) $ requestHeaders req
          }

        ((host, port), newRawPath)
            | isRawPathProxy  = (parseHostPortWithDefault defaultPort hostPortP, newRawPathP)
            | otherwise       = (fromJust hostHeader, rawPath)
          where
            (hostPortP, newRawPathP) = BS8.span (/='/') $
                BS.drop (BS.length rawPathPrefix) rawPath

httpConnectProxy :: ProxySettings -> Middleware
httpConnectProxy pset fallback req respond
    | not isConnectProxy = fallback req respond
    | checkAuth pset req = respond response
    | otherwise          = respond (proxyAuthRequiredResponse pset)
  where
    hostPort' = parseHostPort (rawPathInfo req) <|> (requestHeaderHost req >>= parseHostPort)
    isConnectProxy = requestMethod req == "CONNECT" && isJust hostPort'

    Just (host, port) = hostPort'
    settings = CN.clientSettings port host

    backup = responseLBS HT.status500 [("Content-Type", "text/plain")]
        "HTTP CONNECT tunneling detected, but server does not support responseRaw"

    tryAndCatchAll :: IO a -> IO (Either SomeException a)
    tryAndCatchAll = try

    response
        | HT.httpMajor (httpVersion req) < 2 = responseRaw (handleConnect True) backup
        | otherwise                          = responseStream HT.status200 [] streaming
      where
        streaming write flush = do
            flush
            handleConnect False (getRequestBodyChunk req) (\bs -> write (BB.fromByteString bs) >> flush)

    handleConnect :: Bool -> IO BS.ByteString -> (BS.ByteString -> IO ()) -> IO ()
    handleConnect http1 fromClient' toClient' = CN.runTCPClient settings $ \server ->
        let toServer = CN.appSink server
            fromServer = CN.appSource server
            fromClient = do
                bs <- liftIO fromClient'
                unless (BS.null bs) (yield bs >> fromClient)
            toClient = awaitForever (liftIO . toClient')
        in do
            when http1 $ runConduit $ yield "HTTP/1.1 200 OK\r\n\r\n" .| toClient
            void $ tryAndCatchAll $ concurrently
                (runConduit (fromClient .| toServer))
                (runConduit (fromServer .| toClient))
