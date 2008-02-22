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

> identifier  ::  Parser String
> identifier  =   many (noneOf " ,")
>
> delimiter  ::  Parser ()
> delimiter  =   skipMany1 ((char ' ') <?> "")

In IPTables you can specify either an IP address, a subnet, or a hostname as
either the source or destination of a rule. We generalize these here with the
|IPTablesAddress| type.

> type Address = String
>
> address  ::  Parser Address
> address  =   identifier
>
> instance Graph Address where
>     graph = putStr

An IPTables target actually describes the action that IPTables will take. Don't
confuse "target" with "destination". A target can be one of the 4 basic types
(ACCEPT, DROP, QUEUE, or RETURN) or the name of another chain.

> data Target =  Accept | Drop | Queue | Return | Chain String
>                deriving (Show, Eq)
>
> target  ::  Parser Target
> target  =   identifier >>= \ s ->
>             case s of
>                    "ACCEPT"  -> return Accept
>                    "DROP"    -> return Drop
>                    "QUEUE"   -> return Queue
>                    "RETURN"  -> return Return
>                    _         -> return $ Chain s

As with targets, there are 4 pre-defined protocols and one for protocol names.

> data Protocol =  TCP | UDP | ICMP | All | Protocol String
>                  deriving (Show, Eq)
>
> protocol  ::  Parser Protocol
> protocol  =   identifier >>= \ s ->
>               case s of
>                      "tcp"   -> return TCP
>                      "udp"   -> return UDP
>                      "icmp"  -> return ICMP
>                      "all"   -> return All
>                      _       -> return $ Protocol s

> data Extra =    DPort DPort
>              |  MStates [MState]
>              |  None
>                 deriving (Show, Eq)
>
> extra  ::  Parser Extra
> extra  =   choice [(try dport), (try mstates)]

> type DPort = (Protocol, String)
>
> dport  ::  Parser Extra
> dport  =   protocol >>= \ p ->
>            delimiter >>
>            string "dpt" >> option ' ' (char 's') >> char ':' >>
>            identifier >>= \ i ->
>            return (DPort (p, i))

> data MState =  New | Related | Established | Invalid
>                deriving (Show, Eq)
>
> mstate  ::  Parser MState
> mstate  =   identifier >>= \ s ->
>             case s of
>                    "NEW"          -> return New
>                    "RELATED"      -> return Related
>                    "ESTABLISHED"  -> return Established
>                    "INVALID"      -> return Invalid
>                    _              -> unexpected "invalid state"

> mstates  ::  Parser Extra
> mstates  =   string "state" >> delimiter >>
>              mstate `sepBy` (char ',') >>=
>              return . MStates

> data Rule = Rule {  packets         :: Integer,
>                     bytes           :: Integer,
>                     action          :: Target,
>                     proto           :: Protocol,
>                     options         :: String,
>                     inInterface     :: String,
>                     outInterface    :: String,
>                     source          :: Address,
>                     destination     :: Address,
>                     extras          :: [Extra] }
>             deriving Show
>
> instance Graph Rule where
>     graph r =  graph (source r) >> putStr " -> " >>
>                graph (destination r) >> putStr "\n"

> rule  ::  Parser Rule
> rule  =   skipMany delimiter  >> many1 digit  >>= \ packets ->
>                    delimiter  >> many1 digit  >>= \ bytes ->
>                    delimiter  >> target       >>= \ action ->
>                    delimiter  >> protocol     >>= \ protocol ->
>                    delimiter  >> identifier   >>= \ options ->
>                    delimiter  >> identifier   >>= \ inInterface ->
>                    delimiter  >> identifier   >>= \ outInterface ->
>                    delimiter  >> address      >>= \ source ->
>                    delimiter  >> address      >>= \ destination ->
>                    delimiter  >> extra `sepEndBy` delimiter >>= \ extra ->
>                    newline >>
>                    return (Rule
>                            {  packets       = (read packets),
>                               bytes         = (read bytes),
>                               action        = action,
>                               proto         = protocol,
>                               options       = options,
>                               inInterface   = inInterface,
>                               outInterface  = outInterface,
>                               source        = source,
>                               destination   = destination,
>                               extras        = extra })

> chainHeader  ::  Parser String
> chainHeader  =   string "Chain " >> identifier >>= \name ->
>                  manyTill anyChar newline >>
>                  return name

> chain  ::  Parser (String, [Rule])
> chain  =   chainHeader >>= \name ->
>            manyTill anyChar newline >>
>            manyTill  rule
>                      (newline <|> (eof >> return '\n')) >>= \rules ->
>            return (name, rules)

> chains  ::  Parser [(String, [Rule])]
> chains  =   many1 chain

> main = getContents >>= graphviz

TODO: How can we use lazy evaluation to graph as we parse?

> graphviz    ::  String -> IO ()
> graphviz x  =   case (parse chains "" x) of
>                 Left err  -> print err
>                 Right cs  -> mapM_ graphChain cs

> graphChain                        ::  (String, [Rule]) -> IO ()
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