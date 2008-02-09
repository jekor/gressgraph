> module Main where

> import Data.Word
> import Data.Bits
> import Numeric
> import Text.ParserCombinators.Parsec

> type Octet = Word8
> type IPv4Address = (Octet, Octet, Octet, Octet)
> type IPv4Netmask = IPv4Address
> type IPv4Subnet = (IPv4Address, IPv4Netmask)
> data IPTablesTarget = Address IPv4Address | Subnet IPv4Subnet
>                       deriving Show
> data IPTablesAction = Drop | Accept
>                       deriving Show
> data IPTablesProtocol = TCP | UDP | ICMP | All
>                         deriving Show
> type IPTablesDestPort = (IPTablesProtocol, Int)
> data IPTablesState = NEW | RELATED | ESTABLISHED | INVALID
>                      deriving Show
> data IPTablesExtra = DestPort IPTablesDestPort | IState IPTablesState
>                      deriving Show

> toOctet :: Num a => a -> Octet
> toOctet x = read $ show x

> octet :: Parser Octet
> octet = many1 digit >>= \x ->
>         let oct::Integer = read x in
>             if oct < 0 || oct > 255
>             then unexpected "integer (octets are between 0 and 255)"
>             else return (toOctet oct)
>         <?> "octet"

> ipv4address :: Parser IPv4Address
> ipv4address = octet >>= \o1 ->
>               char '.' >> octet >>= \o2 ->
>               char '.' >> octet >>= \o3 ->
>               char '.' >> octet >>= \o4 ->
>               return (o1, o2, o3, o4)
>               <?> "IPv4 address"

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
>        <?> "CIDR suffix"

> ipv4netmask :: Parser IPv4Netmask
> ipv4netmask = try ipv4address <|> cidr
>               <?> "IPv4 netmask"

> ipv4subnet :: Parser IPv4Subnet
> ipv4subnet = ipv4address >>= \a ->
>              char '/' >> ipv4netmask >>= \n ->
>              return (a, n)
>              <?> "IPv4 subnet"

> iptablesTarget :: Parser IPTablesTarget
> iptablesTarget = ipv4address >>= \a ->
>                  try (char '/' >> ipv4netmask >>= \n ->
>                       return (Subnet (a, n))) <|>
>                  return (Address a)
>                  <?> "IPTables target"

> iptablesAction :: Parser IPTablesAction
> iptablesAction = many1 letter >>= \a ->
>                  case a of
>                    "DROP"    -> return Drop
>                    "ACCEPT"  -> return Accept
>                    _         -> unexpected "invalid action"
>                  <?> "IPTables action"

> iptablesProtocol :: Parser IPTablesProtocol
> iptablesProtocol = many1 letter >>= \p ->
>                    case p of
>                      "all" -> return All
>                      "tcp" -> return TCP
>                      "udp" -> return UDP
>                      _     -> unexpected "invalid protocol"
>                    <?> "IPTables protocol"

> iptablesDestPort :: Parser IPTablesExtra
> iptablesDestPort = space >> iptablesProtocol >>= \p ->
>                    space >> string "dpt:" >>
>                    many1 digit >>= \d ->
>                    return (DestPort (p, (read d)))
>                    <?> "IPTables destination port"

> iptablesState :: Parser IPTablesExtra
> iptablesState = string " state " >>
>                 many1 letter >>= \s ->
>                 case s of
>                   "NEW"         -> return (IState NEW)
>                   "RELATED"     -> return (IState RELATED)
>                   "ESTABLISHED" -> return (IState ESTABLISHED)
>                   "INVALID"     -> return (IState INVALID)
>                   _             -> unexpected "invalid state"
>                 <?> "IPTables state"

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
>                   deriving Show

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
>                manyTill (choice [(try iptablesState), (try iptablesDestPort)]) (char '\n') >>= \e ->
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
>                <?> "IPTables rule"
>     where interface = many1 (letter <|> char '*')

> iptablesChainHeader :: Parser String
> iptablesChainHeader = string "Chain " >> many1 (letter) >>= \name ->
>                       many1 (noneOf "\n") >>
>                       return name
>                       <?> "IPTables chain header"

> iptablesChain :: Parser (String, [IPTablesRule])
> iptablesChain = iptablesChainHeader >>= \name ->
>                 char '\n' >> many iptablesRule >>= \rules ->
>                 char '\n' >>
>                 return (name, rules)
>                 <?> "IPTables chain"

> iptablesChains :: Parser [(String, [IPTablesRule])]
> iptablesChains = many iptablesChain
>                  <?> "IPTables listing"

> main = parseTest iptablesChains