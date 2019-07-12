-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2019 Bin Jin. All Rights Reserved.
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}

module Main where

import           Control.Concurrent          (ThreadId, forkIO)
import qualified Data.Set                    as Set
import qualified Data.ByteString.Char8       as BS8
import           Data.String                 (fromString)
import qualified Data.Text.Encoding          as TE

import           Database.SQLite.Simple

import qualified Network.HTTP.Client         as HC
import           Network.TLS                 as TLS
import           Network.Wai.Handler.Warp    (HostPreference, defaultSettings,
                                              runSettings, setBeforeMainLoop,
                                              setHost, setNoParsePath, setPort,
                                              setServerName)
import           Network.Wai.Handler.WarpTLS (OnInsecure (..), onInsecure,
                                              runTLS, tlsServerHooks,
                                              tlsSettings)
import           Network.Wai.Middleware.Gzip (def, gzip)
import           System.Posix.User           (UserEntry (..),
                                              getUserEntryForName, setUserID)

import           Data.Maybe
import           Data.Monoid                 ((<>))
import           Options.Applicative

import           HProx                       (ProxySettings (..), dumbApp,
                                              forceSSL, httpProxy, reverseProxy, adminApp)

data Opts = Opts
  { _bind  :: Maybe HostPreference
  , _pport  :: Int
  , _aport :: Int
  , _ssl   :: [(String, CertFile)]
  , _user  :: Maybe String
  , _auth  :: Maybe FilePath
  , _ws    :: Maybe String
  , _rev   :: Maybe String
  , _black :: Maybe String
  }

data CertFile = CertFile
  { certfile :: FilePath
  , keyfile  :: FilePath
  }

adminPort :: Int
adminPort = 3333 

proxyPort :: Int
proxyPort = 3000 

readCert :: CertFile -> IO TLS.Credential
readCert (CertFile c k) = either error id <$> TLS.credentialLoadX509 c k

splitBy :: Eq a => a -> [a] -> [[a]]
splitBy _ [] = [[]]
splitBy c (x:xs)
  | c == x    = [] : splitBy c xs
  | otherwise = let y:ys = splitBy c xs in (x:y):ys

parser :: ParserInfo Opts
parser = info (helper <*> opts) fullDesc
  where
    parseSSL s = case splitBy ':' s of
        [host, cert, key] -> Right (host, CertFile cert key)
        _                 -> Left "invalid format for ssl certificates"

    opts = Opts <$> bind_
                <*> (fromMaybe proxyPort <$> pport)
                <*> (fromMaybe adminPort <$> aport)
                <*> ssl
                <*> user
                <*> auth
                <*> ws
                <*> rev
                <*> blacklist

    bind_ = optional $ fromString <$> strOption
        ( long "bind"
       <> short 'b'
       <> metavar "bind_ip"
       <> help "ip address to bind on (default: all interfaces)")

    pport = optional $ option auto
        ( long "pport"
       <> short 'p'
       <> metavar "port"
       <> help ("proxy port number (default " <> show proxyPort <> ")"))
    
    aport = optional $ option auto
        ( long "aport"
       <> metavar "port"
       <> help ("admin port number (default " <> show adminPort <> ")"))

    ssl = many $ option (eitherReader parseSSL)
        ( long "tls"
       <> short 's'
       <> metavar "hostname:cerfile:keyfile"
       <> help "enable TLS and specify a domain and associated TLS certificate (can be specified multiple times for multiple domains)")

    user = optional $ strOption
        ( long "user"
       <> short 'u'
       <> metavar "nobody"
       <> help "setuid after binding port")

    auth = optional $ strOption
        ( long "auth"
       <> short 'a'
       <> metavar "userpass.txt"
       <> help "password file for proxy authentication (plain text file with lines each containing a colon separated user/password pair)")

    ws = optional $ strOption
        ( long "ws"
       <> metavar "remote-host:80"
       <> help "remote host to handle websocket requests (HTTP server only)")

    rev = optional $ strOption
        ( long "rev"
       <> metavar "remote-host:80"
       <> help "remote host for reverse proxy (HTTP server only)")
    
    blacklist = optional $ strOption
        ( long "bl"
       <> metavar "blacklist.txt"
       <> help "blacklist file path (plain text file with lines each containing a hostname)")


setuid :: String -> IO ()
setuid user = getUserEntryForName user >>= setUserID . userID

main :: IO ()
main = do
    opts    <- execParser parser
    (isSSL, runnerProxy, runnerService) <- setupRunners opts

    conn    <- setupStorage "t-o-s.db"
    proxy   <- setupProxy isSSL opts conn

    let (proxySettings, serviceSettings) = setupSettings opts

    putStrLn "Checking blacklists"
    importBlacklist opts conn

    putStrLn "Running service thread"
    _adminWorkerThreadId :: ThreadId <- forkIO $ runnerService serviceSettings (adminApp conn) 

    putStrLn "Running proxy thread"
    runnerProxy proxySettings proxy

    where
      setupProxy isSSL opts conn = do
        pauth   <- setupAuth opts
        manager <- HC.newManager HC.defaultManagerSettings
        let pset = ProxySettings pauth Nothing (BS8.pack <$> _ws opts) (BS8.pack <$> _rev opts)
        pure $ (if isSSL then forceSSL else id) $ gzip def $ httpProxy conn pset manager $ reverseProxy pset manager dumbApp

      setupSettings opts = 
        let settings = setNoParsePath False $
                       setServerName "Traffic-o-scope" $
                       maybe id (setBeforeMainLoop . setuid) (_user opts)
                       defaultSettings

            serviceSettings = setHost (fromMaybe "*6" (_bind opts)) $ setPort (_aport opts) settings
            proxySettings   = setHost (fromMaybe "*6" (_bind opts)) $ setPort (_pport opts) settings
        in (proxySettings, serviceSettings)

      setupAuth opts = do
        case _auth opts of
          Nothing -> pure Nothing
          Just f  -> Just . flip elem . filter (isJust . BS8.elemIndex ':') . BS8.lines <$> BS8.readFile f

      setupRunners opts = do 
        let certfiles = _ssl opts
            isSSL     = not (null certfiles)

        certs <- mapM (readCert . snd) certfiles
        let (runnerProxy, runnerService) = if isSSL then setupSSL certfiles certs else setupNoSSL

        pure (isSSL, runnerProxy, runnerService)

      setupSSL certfiles certs = 
        let (primaryHost, primaryCert) = head certfiles
            otherCerts = tail $ zip (map fst certfiles) certs

            tlsset' = tlsSettings (certfile primaryCert) (keyfile primaryCert)
            hooks   = (tlsServerHooks tlsset') { onServerNameIndication = onSNI }
            tlsset  = tlsset' { tlsServerHooks = hooks, onInsecure = AllowInsecure }

            failSNI = fail "SNI" >> return mempty
            onSNI x = print x >> go x

            go Nothing = failSNI
            go (Just host)
              | host == primaryHost = return mempty
              | otherwise           = case lookup host otherCerts of
                  Nothing   -> failSNI
                  Just cert -> return (TLS.Credentials [cert])

        -- in (runTLS tlsset, runTLS tlsset)
        in (runSettings, runTLS tlsset)

      setupNoSSL = (runSettings, runSettings)

      setupStorage dbname = do
        conn <- open dbname
        execute_ conn "CREATE TABLE IF NOT EXISTS blacklist (id INTEGER PRIMARY KEY, domainname TEXT)"
        execute_ conn "CREATE TABLE IF NOT EXISTS blocked (datetime TEXT, domainname TEXT, request TEXT)"
        execute_ conn "CREATE TABLE IF NOT EXISTS allowed (datetime TEXT, domainname TEXT)"
        pure conn

      importBlacklist opts conn = do
        case _black opts of
          Nothing -> do
            putStrLn "Using existing blacklist"
                
          Just f  -> do
            xs <- Set.fromList . fmap TE.decodeUtf8 . filter ((> 0) . BS8.length) . BS8.lines <$> BS8.readFile f
            putStrLn $ "Importing new blacklist of " <> show (Set.size xs) <> " entries."
            executeMany conn "INSERT INTO blacklist (domainname) VALUES (?)" $ fmap Only (Set.toList xs)
            execute conn "delete from blacklist where rowid not in (select min(rowid) from blacklist group by domainname)" ()
            
