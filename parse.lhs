> module Main where

> import Data.Word
> import Data.Bits
> import Data.List
> import Numeric
> import Text.ParserCombinators.Parsec
> import Text.ParserCombinators.Parsec.Prim

> type Octet = Word8
> type IPv4Address = (Octet, Octet, Octet, Octet)
> type IPv4Netmask = IPv4Address
> type IPv4Subnet = (IPv4Address, IPv4Netmask)
> data IPTablesTarget = Address IPv4Address | Subnet IPv4Subnet | Hostname String
>                       deriving Show
> data IPTablesAction = Drop | Accept
>                       deriving Show
> data IPTablesProtocol = TCP | UDP | ICMP | All
>                         deriving Show
> data IPTablesPort = PortNumber Int | PortName String
>                     deriving Show
> type IPTablesDestPort = (IPTablesProtocol, (IPTablesPort, IPTablesPort))
> data IPTablesState = NEW | RELATED | ESTABLISHED | INVALID
>                      deriving Show
> data IPTablesExtra = DestPort IPTablesDestPort | IState [IPTablesState] | None
>                      deriving Show

An identifier is any series of alphanumeric characters that doesn't start with
a number.

> identifier :: Parser String
> identifier = letter >>= \x ->
>              many (alphaNum <|> (char '-')) >>= \xs ->
>              return (x:xs)

> toOctet :: Num a => a -> Octet
> toOctet x = read $ show x

> octet :: Parser Octet
> octet = many1 digit >>= \x ->
>         let oct::Integer = read x in
>             if oct < 0 || oct > 255
>             then unexpected "integer (octets are between 0 and 255)"
>             else return (toOctet oct)

> ipv4address :: Parser IPv4Address
> ipv4address = octet >>= \o1 ->
>               char '.' >> octet >>= \o2 ->
>               char '.' >> octet >>= \o3 ->
>               char '.' >> octet >>= \o4 ->
>               return (o1, o2, o3, o4)

> toIPv4Address :: Word32 -> IPv4Address
> toIPv4Address ip =
>   (toOctet $ shiftR (ip .&. 0xFF000000) 0o30,
>    toOctet $ shiftR (ip .&. 0x00FF0000) 0o20,
>    toOctet $ shiftR (ip .&. 0x0000FF00) 0o10,
>    toOctet (ip .&. 0x000000FF))

> fromCIDR :: Int -> IPv4Netmask
> fromCIDR x = toIPv4Address $ shift 0xFFFFFFFF (32 - x)

> cidr :: Parser IPv4Netmask
> cidr = many1 digit >>= \x ->
>        let bits::Int  = read x in
>            if bits < 0 || bits > 32
>            then unexpected "integer (CIDR suffixes are between 0 and 32)"
>            else return (fromCIDR bits)

> ipv4netmask :: Parser IPv4Netmask
> ipv4netmask = try ipv4address <|> try cidr
>               <?> "IPv4 netmask"

> ipv4subnet :: Parser IPv4Subnet
> ipv4subnet = ipv4address >>= \a ->
>              char '/' >> ipv4netmask >>= \n ->
>              return (a, n)

> iptablesTarget :: Parser IPTablesTarget
> iptablesTarget = try (identifier >>= \i -> return (Hostname i)) <|>
>                  (ipv4address >>= \a ->
>                   try (char '/' >> ipv4netmask >>= \n ->
>                        return (Subnet (a, n))) <|>
>                   return (Address a))

> iptablesAction :: Parser IPTablesAction
> iptablesAction = many1 letter >>= \a ->
>                  case a of
>                    "DROP"    -> return Drop
>                    "ACCEPT"  -> return Accept
>                    _         -> unexpected "invalid action"

> iptablesProtocol :: Parser IPTablesProtocol
> iptablesProtocol = many1 letter >>= \p ->
>                    case p of
>                      "all" -> return All
>                      "tcp" -> return TCP
>                      "udp" -> return UDP
>                      _     -> unexpected "invalid protocol"

> iptablesPort :: Parser IPTablesPort
> iptablesPort = try (many1 digit >>= \p -> return (PortNumber (read p)))
>                <|> (identifier >>= \n -> return (PortName n))

> iptablesDestPort :: Parser (IPTablesPort, IPTablesPort)
> iptablesDestPort = string "dpt:" >>
>                    iptablesPort >>= \p -> return (p, p)

> iptablesDestPortRange :: Parser (IPTablesPort, IPTablesPort)
> iptablesDestPortRange = string "dpts:" >>
>                         iptablesPort >>= \begin ->
>                         char ':' >>
>                         iptablesPort >>= \end ->
>                         return (begin, end)

> iptablesDPort :: Parser IPTablesExtra
> iptablesDPort = iptablesProtocol >>= \p ->
>                 space >> ((try iptablesDestPort) <|> iptablesDestPortRange) >>= \d ->
>                 return (DestPort (p, d))

> iptablesState :: Parser IPTablesState
> iptablesState = many1 letter >>= \s ->
>                 case s of
>                   "NEW"         -> return NEW
>                   "RELATED"     -> return RELATED
>                   "ESTABLISHED" -> return ESTABLISHED
>                   "INVALID"     -> return INVALID
>                   _             -> unexpected "invalid state"

> iptablesStates :: Parser IPTablesExtra
> iptablesStates = string "state " >>
>                  iptablesState `sepBy` (char ',') >>= \s ->
>                  return (IState s)

> data IPTablesRule =
>   IPTablesRule { packets :: Integer,
>                  bytes   :: Integer,
>                  action  :: IPTablesAction,
>                  protocol :: IPTablesProtocol,
>                  options :: String,
>                  inInterface :: String,
>                  outInterface :: String,
>                  source :: IPTablesTarget,
>                  destination :: IPTablesTarget,
>                  extra :: [IPTablesExtra] }
>   deriving Show

> iptablesRule :: Parser IPTablesRule
> iptablesRule = many space >>
>                many1 digit >>= \packets ->
>                many1 space >> many1 digit >>= \bytes ->
>                many1 space >> iptablesAction >>= \action ->
>                many1 space >> iptablesProtocol >>= \protocol ->
>                many1 space >> many1 (letter <|> char '-') >>= \options ->
>                many1 space >> interface >>= \inInterface ->
>                many1 space >> interface >>= \outInterface ->
>                many1 space >> iptablesTarget >>= \source ->
>                many1 space >> iptablesTarget >>= \destination ->
>                manyTill (choice [(many1 (char ' ') >> return None), (try iptablesStates), (try iptablesDPort)]) newline >>= \e ->
>                return (IPTablesRule
>                        { packets=(read packets),
>                          bytes=(read bytes),
>                          action=action,
>                          protocol=protocol,
>                          options=options,
>                          inInterface=inInterface,
>                          outInterface=outInterface,
>                          source=source,
>                          destination=destination,
>                          extra=e })
>     where interface = try (string "*") <|> identifier

> iptablesChainHeader :: Parser String
> iptablesChainHeader = string "Chain " >> many1 (letter) >>= \name ->
>                       manyTill anyChar newline >>
>                       return name

> iptablesChain :: Parser (String, [IPTablesRule])
> iptablesChain = iptablesChainHeader >>= \name ->
>                 manyTill anyChar newline >>
>                 manyTill iptablesRule (newline <|> (eof >> return '\n')) >>= \rules ->
>                 return (name, rules)

> iptablesChains :: Parser [(String, [IPTablesRule])]
> iptablesChains = many1 iptablesChain

> main = getContents >>= graphviz

> graphviz :: String -> IO ()
> graphviz x = case (parse iptablesChains "" x) of
>                Left err -> print err
>                Right cs -> mapM_ graphChain cs

> graphChain :: (String, [IPTablesRule]) -> IO ()
> graphChain ("INPUT", rules) = mapM_ graphRule rules
> graphChain (_, _) = return ()

> graphRule :: IPTablesRule -> IO ()
> graphRule = print

Graphviz uses a limited set of ASCII characters for node identifiers.

> tr :: Eq a => [a] -> [(a, a)] -> [a]
> tr []     _ = []
> tr (x:xs) p = y:(tr xs p)
>     where y   = case rep of
>                   Nothing -> x
>                   Just z -> snd z
>           rep = find (((==) x) . fst) p

> nodeName :: String -> String
> nodeName n = tr n [('.', '_')]