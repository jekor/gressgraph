\documentclass[oneside]{article}
%include polycode.fmt
\usepackage[T1]{fontenc}
\begin{document}

The purpose of FIXME is to help you visualize your IPTables firewall. It
acts as a filter, translating your firewall rules from IPTables format into
Graphviz graphing instructions.

You can create a simple graph of your firewall with:

\begin{verbatim}
$ iptables -L -vx | FIXME > iptables.dot
$ dot -Tpng iptables.dot > iptables.png
\end{verbatim}

(You can use \verb!-Tsvg! instead of \verb!-Tpng! if you want vector output.)

The program begins here. It's written in Haskell98 and uses Glasgow extensions.
It's been tested with GHC 6.8.2.

> module Main where
> import Numeric
> import Data.Word
> import Data.Bits
> import Data.List
> import Text.ParserCombinators.Parsec
> import Text.ParserCombinators.Parsec.Prim

We need to be able to "graph" (output in a format that Graphviz will
understand) an IPTables chain. To do so, we delegate the task of graphing
to each IPTables type.

> class Graph a where
>     graph :: a -> IO ()

The first type we need to represent is an IP address. We could use a 32-bit
integer, but I've decided to use individual octets since it fits closer to
the way we normally think of IP addresses (in dotted form).

An |Octet| is an 8-bit (unsigned) integer.

> type Octet = Word8

To parse an |Octet|, we just need to read a sequence of numbers and make sure
they're in the range $[0, 255]$.

> octet  ::  Parser Octet
> octet  =   many1 digit >>= octet' . read
>     where octet' x  | x >= 0 && x <= 255  = return $ toOctet x
>                     | otherwise           = unexpected "integer > 255"
>            <?> "octet"

We need |toOctet| as a hack to convert Integer values into |Octet|s. This will
always produce an integer in the range $[0, 255]$ by discarding bits if it has
to. (There must be a better way to do this.)

> toOctet  :: Integral a => a -> Octet
> toOctet  = read . show

We'll use a list of |Octet|s to represent an IPv4 address. (A quadruple would
be more correct but makes the code more complex.)

> type IPv4Address = [Octet]

To graph, we just print the octets with \verb!.! between them. The parsing is
similarly simple.

> instance Graph IPv4Address where
>     graph = putStr . (intercalate ".") . (map show)
>
> ipv4Address  ::  Parser IPv4Address
> ipv4Address  =   sepBy1 octet (char '.')

An IP netmask can be represented as an IP address since it's essentially a
32-bit mask. It may be written in shortened /CIDR form, which we'll need to
deal with when parsing.

> type IPv4Netmask = IPv4Address

We need to try matching a CIDR first, since our ipv4Address rule accepts almost
anything.

> ipv4Netmask  ::  Parser IPv4Netmask
> ipv4Netmask  =   try cidr <|> try ipv4Address
>                  <?> "IPv4 netmask"

A CIDR takes the form \verb!/CIDR! where \verb!CIDR! is in the range $[0, 32]$.

> cidr  ::  Parser IPv4Netmask
> cidr  =   many1 digit >>= cidr' . read
>    where cidr' x  | x >= 0 && x <= 32  = return $ fromCIDR x
>                   | otherwise          = unexpected "integer > 32"
>           <?> "CIDR suffix"

To think about how to convert the netmask in CIDR form into an IP address, it
helps to visualize what's happening.

A CIDR of 8 means that we want to mask out the least significant 8 bits of
addresses.

> fromCIDR  ::  Int -> IPv4Netmask
> fromCIDR  =   toIPv4Address . (shift 0xFFFFFFFF) . (32 -)

We end up with a 32-bit integer, but what we want is an IP address.

> toIPv4Address     ::  Word32 -> IPv4Address
> toIPv4Address ip  =
>     [  toOctet $ shiftR  (ip .&. 0xFF000000) 0o30,
>        toOctet $ shiftR  (ip .&. 0x00FF0000) 0o20,
>        toOctet $ shiftR  (ip .&. 0x0000FF00) 0o10,
>        toOctet           (ip .&. 0x000000FF)       ]

A subnet is a combination of an IP address an a netmask to mask out the
insignificant bits.

> type IPv4Subnet = (IPv4Address, IPv4Netmask)
>
> instance Graph IPv4Subnet where
>     graph (a, n) = graph a >> putStr "/" >> graph n
>
> ipv4Subnet  ::  Parser IPv4Subnet
> ipv4Subnet  =   ipv4Address >>= \a ->
>                 char '/' >> ipv4Netmask >>= \n ->
>                 return (a, n)

In IPTables you can specify either an IP address, a subnet, or a hostname as
either the source or destination of a rule. We generalize these here with the
|IPTablesAddress| type.

> data IPTablesAddress  =    Address   IPv4Address
>                         |  Subnet    IPv4Subnet
>                         |  Hostname  String
>                            deriving Show
>
> instance Graph IPTablesAddress where
>     graph (Hostname  x)  = putStr x
>     graph (Address   x)  = graph x
>     graph (Subnet    x)  = graph x

An IPTables target actually describes the action that IPTables will take. Don't
confuse "target" with "destination". A target can be one of the 4 basic types
(ACCEPT, DROP, QUEUE, or RETURN) or the name of another chain.

> data IPTablesTarget =  Accept | Drop | Queue | Return | Chain String
>                        deriving (Show, Eq)
>
> iptablesTarget  ::  Parser IPTablesTarget
> iptablesTarget  =   many1 letter >>= \s ->
>                     case s of
>                            "ACCEPT"  -> return Accept
>                            "DROP"    -> return Drop
>                            "QUEUE"   -> return Queue
>                            "RETURN"  -> return Return
>                            _         -> return $ Chain s

As with targets, there are 4 pre-defined protocols and one for protocol names.

> data IPTablesProtocol =  TCP | UDP | ICMP | All | Protocol String
>                          deriving (Show, Eq)
>
> iptablesProtocol  ::  Parser IPTablesProtocol
> iptablesProtocol  =   many1 letter >>= \s ->
>                       case s of
>                              "tcp"   -> return TCP
>                              "udp"   -> return UDP
>                              "icmp"  -> return ICMP
>                              "all"   -> return All
>                              _       -> return $ Protocol s

> data IPTablesPort =  PortNumber Int | PortName String
>                      deriving (Show, Eq)
> type IPTablesDestPort = (IPTablesProtocol, (IPTablesPort, IPTablesPort))
> data IPTablesState =  New | Related | Established | Invalid
>                       deriving (Show, Eq)
> data IPTablesExtra =    DestPort IPTablesDestPort
>                      |  IState [IPTablesState]
>                      |  None
>                         deriving (Show, Eq)

An identifier is any series of alphanumeric characters that doesn't start with
a number.

> identifier  ::  Parser String
> identifier  =   letter >>= \x ->
>                 many (alphaNum <|> (char '-')) >>= \xs ->
>                 return (x:xs)

> iptablesAddress  ::  Parser IPTablesAddress
> iptablesAddress  =   try (identifier >>= \i -> return (Hostname i)) <|>
>                      (ipv4Address >>= \a ->
>                       try (char '/' >> ipv4Netmask >>= \n ->
>                            return (Subnet (a, n))) <|>
>                       return (Address a))

> iptablesPort  ::  Parser IPTablesPort
> iptablesPort  =   try (many1 digit >>= \p -> return (PortNumber (read p)))
>                   <|> (identifier >>= \n -> return (PortName n))

> iptablesDestPort  ::  Parser (IPTablesPort, IPTablesPort)
> iptablesDestPort  =   string "dpt:" >>
>                       iptablesPort >>= \p -> return (p, p)

> iptablesDestPortRange  ::  Parser (IPTablesPort, IPTablesPort)
> iptablesDestPortRange  =   string "dpts:" >>
>                            iptablesPort >>= \begin ->
>                            char ':' >>
>                            iptablesPort >>= \end ->
>                            return (begin, end)

> iptablesDPort  ::  Parser IPTablesExtra
> iptablesDPort  =   iptablesProtocol >>= \p ->
>                    space >>  ((try iptablesDestPort) <|>
>                               iptablesDestPortRange) >>= \d ->
>                    return (DestPort (p, d))

> iptablesState  ::  Parser IPTablesState
> iptablesState  =   many1 letter >>= \s ->
>                    case s of
>                           "NEW"          -> return New
>                           "RELATED"      -> return Related
>                           "ESTABLISHED"  -> return Established
>                           "INVALID"      -> return Invalid
>                           _              -> unexpected "invalid state"

> iptablesStates  ::  Parser IPTablesExtra
> iptablesStates  =   string "state " >>
>                     iptablesState `sepBy` (char ',') >>= \s ->
>                     return (IState s)

> data IPTablesRule =
>   IPTablesRule {  packets         :: Integer,
>                   bytes           :: Integer,
>                   action          :: IPTablesTarget,
>                   protocol        :: IPTablesProtocol,
>                   options         :: String,
>                   inInterface     :: String,
>                   outInterface    :: String,
>                   source          :: IPTablesAddress,
>                   destination     :: IPTablesAddress,
>                   extra           :: [IPTablesExtra] }
>   deriving Show
>
> instance Graph IPTablesRule where
>     graph r =  graph (source r) >> putStr " -> " >>
>                graph (destination r) >> putStr "\n"

> iptablesRule  ::  Parser IPTablesRule
> iptablesRule  =   many space >>
>                   many1 digit >>= \packets ->
>                   many1 space >> many1 digit >>= \bytes ->
>                   many1 space >> iptablesTarget >>= \action ->
>                   many1 space >> iptablesProtocol >>= \protocol ->
>                   many1 space >> many1 (letter <|> char '-') >>= \options ->
>                   many1 space >> interface >>= \inInterface ->
>                   many1 space >> interface >>= \outInterface ->
>                   many1 space >> iptablesAddress >>= \source ->
>                   many1 space >> iptablesAddress >>= \destination ->
>                   manyTill  (choice [  (many1 (char ' ') >> return None),
>                                        (try iptablesStates),
>                                        (try iptablesDPort)])
>                             newline >>= \e ->
>                   return (IPTablesRule
>                           {  packets       = (read packets),
>                              bytes         = (read bytes),
>                              action        = action,
>                              protocol      = protocol,
>                              options       = options,
>                              inInterface   = inInterface,
>                              outInterface  = outInterface,
>                              source        = source,
>                              destination   = destination,
>                              extra         = (filter ((/=) None) e) })
>     where interface = try (string "*") <|> identifier

> iptablesChainHeader  ::  Parser String
> iptablesChainHeader  =   string "Chain " >> many1 (letter) >>= \name ->
>                          manyTill anyChar newline >>
>                          return name

> iptablesChain  ::  Parser (String, [IPTablesRule])
> iptablesChain  =  iptablesChainHeader >>= \name ->
>                   manyTill anyChar newline >>
>                   manyTill  iptablesRule
>                             (newline <|> (eof >> return '\n')) >>= \rules ->
>                   return (name, rules)

> iptablesChains  ::  Parser [(String, [IPTablesRule])]
> iptablesChains  =   many1 iptablesChain

> main = getContents >>= graphviz

> graphviz    ::  String -> IO ()
> graphviz x  =   case (parse iptablesChains "" x) of
>                 Left err  -> print err
>                 Right cs  -> mapM_ graphChain cs

> graphChain                        ::  (String, [IPTablesRule]) -> IO ()
> graphChain ("INPUT"  ,  rules  )  =   mapM_ graph rules
> graphChain (_        ,  _      )  =   return ()

Graphviz uses a limited set of ASCII characters for node identifiers.

> tr             ::  Eq a => [a] -> [(a, a)] -> [a]
> tr  []      _  =   []
> tr  (x:xs)  p  =   y:(tr xs p)
>     where  y    =  case rep of
>                    Nothing  -> x
>                    Just z   -> snd z
>            rep  = find (((==) x) . fst) p

> nodeName    ::  String -> String
> nodeName n  =   tr n [('.', '_')]

\end{document}