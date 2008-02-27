\documentclass[oneside]{article}
%include polycode.fmt
\usepackage[T1]{fontenc}

\newcommand{\iptables}{{\sc IpT}ables}
% lhs2TeX doesn't format the <|> (choice) operator from Parsec well. We'll use
% the symbol used by Philip Wadler in "Comprehending Monads" to indicate the
% "alternation" operator.
%format <|> = "\talloblong{}"

\begin{document}

The purpose of \verb!ingressgraph! is to help you visualize your \iptables{} firewall.
It acts as a filter, translating your firewall rules from \iptables{} format into
Graphviz graphing instructions.

You can create a simple graph of your firewall with:

\begin{verbatim}
$ iptables -L -vx | ingressgraph > iptables.dot
$ dot -Tpng iptables.dot > iptables.png
\end{verbatim}

(Use \verb!-Tsvg! instead of \verb!-Tpng! if you want vector output.)
\vskip 2em
The program begins here. It's written in Haskell98 and uses Glasgow extensions.
It's been tested with {\sc Ghc} 6.8.2.

> module Main where
> import Data.Char
> import Data.List
> import Text.ParserCombinators.Parsec
> import Text.ParserCombinators.Parsec.Prim

We need to be able to ``graph'' (output in a format that Graphviz will
understand) an \iptables{} chain. To do so, we delegate the task of graphing
to each \iptables{} type.

> class Graph a where
>     graph :: a -> IO ()

We need some basic parsers for \iptables{} syntax. These are very permissive,
trading simplicity for safety since we don't expect \verb!iptables! to give us
malformed data.

> identifier  ::  Parser String
> identifier  =   many (noneOf " ,")
>
> delimiter  ::  Parser ()
> delimiter  =   skipMany1 (char ' ')

An \iptables{} target actually describes the action that \iptables{} will take.
Don't confuse ``target'' with ``destination''. A target can be one of the 4
basic types ({\sc accept, drop, queue}, or {\sc queue}) or the name of another
chain.

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
>                    _         -> return (Chain s)

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
>                      _       -> return (Protocol s)

\iptables{} allows for ``extra'' options. These are things like
destination port, connection state, etc. This is where a lot of the meat of the
rule is and is the (relatively) difficult part to parse.

> data Extra =  DPort    DPort     |
>               CStates  [CState]  |
>               None
>               deriving (Show, Eq)
>
> extra  ::  Parser Extra
> extra  =   choice [  (try dport    >>= return . DPort    ),
>                      (try cstates  >>= return . CStates  )]
>
> extras  ::  Parser [Extra]
> extras  =   extra `sepEndBy` delimiter

A destination port has the form \verb!udp dpt:bootps! or
\verb!tcp dpt:10000:10010!.

> type DPort = (Protocol, String)
>
> dport  ::  Parser DPort
> dport  =   protocol >>= \ p -> delimiter >>
>            string "dpt" >> option ' ' (char 's') >> char ':' >>
>            identifier >>= \ i -> return (p, i)

A connection state can be {\sc new, related, established} or
{\sc invalid}. It allows \iptables{} to determine whether or not to apply a
rule by checking the connection tracking history.

> data CState =  New | Related | Established | Invalid
>                deriving (Show, Eq)
>
> cstate  ::  Parser CState
> cstate  =   identifier >>= \ s ->
>             case s of
>                    "NEW"          -> return New
>                    "RELATED"      -> return Related
>                    "ESTABLISHED"  -> return Established
>                    "INVALID"      -> return Invalid
>                    _              -> unexpected "invalid state"

The state can be (and often is) a list of states separated by a comma.

> cstates  ::  Parser [CState]
> cstates  =   string "state" >> delimiter >>
>              cstate `sepBy` (char ',') >>= return

Here's the main unit of our graph: the \iptables{} rule. In the \verb!iptables!
output it's almost a {\sc csv} line with spaces for delimiters, except for the
``extra'' information.

> data Rule =  Rule {  packets         :: Integer,
>                      bytes           :: Integer,
>                      action          :: Target,
>                      proto           :: Protocol,
>                      options         :: String,
>                      inInterface     :: String,
>                      outInterface    :: String,
>                      source          :: String,
>                      destination     :: String,
>                      extraOpts       :: [Extra] }
>              deriving Show
>
> rule  ::  Parser Rule
> rule  =   skipMany  delimiter  >> many1 digit  >>= \ packets       ->
>                     delimiter  >> many1 digit  >>= \ bytes         ->
>                     delimiter  >> target       >>= \ action        ->
>                     delimiter  >> protocol     >>= \ protocol      ->
>                     delimiter  >> identifier   >>= \ options       ->
>                     delimiter  >> identifier   >>= \ inInterface   ->
>                     delimiter  >> identifier   >>= \ outInterface  ->
>                     delimiter  >> identifier   >>= \ source        ->
>                     delimiter  >> identifier   >>= \ destination   ->
>                     delimiter  >> extras       >>= \ extras        ->
>                     newline >>
>                     return (Rule
>                             {  packets       = (read packets),
>                                bytes         = (read bytes),
>                                action        = action,
>                                proto         = protocol,
>                                options       = options,
>                                inInterface   = inInterface,
>                                outInterface  = outInterface,
>                                source        = source,
>                                destination   = destination,
>                                extraOpts     = extras })

Graphing the |Rule| is where the magic happens.

> instance Graph Rule where
>     graph r = putStr $  quote (source r)       ++  " -> " ++
>                         quote (destination r)  ++  "\n"

A |Chain| is a named collection of rules. The rules are in order (even though
we ignore that for graphing purposes).

> type Chain = (String, [Rule])

A chain is terminated by a newline or the end of file marker.

> chain  ::  Parser Chain
> chain  =   chainHeader >>= \name ->
>            manyTill anyChar newline >>
>            manyTill  rule
>                      (newline <|> (eof >> return '\n')) >>= \rules ->
>            return (name, rules)
>
> chainHeader  ::  Parser String
> chainHeader  =   string "Chain " >> identifier >>= \name ->
>                  manyTill anyChar newline >>
>                  return name

Finally, the \iptables{} output (our input) is a series of chains.

> chains  ::  Parser [Chain]
> chains  =   many1 chain

To graph the chain, we first create nodes with labels for each of the source
and destination addresses. To do so, we first build a list of unique sources
and destinations.

> instance Graph Chain where
>     graph c = mapM_ graphAddress (uniqueAddresses c') >>
>               mapM_ graph c'
>         where c'              = snd c
>               graphAddress a  = putStr $ (quote a) ++
>                                 " [label=\"" ++ a ++ "\"]\n"

> uniqueAddresses  ::  [Rule] -> [String]
> uniqueAddresses  =   nub . concat . (map addresses)

> addresses    ::  Rule -> [String]
> addresses r  =   nub [(source r), (destination r)]

Graphviz uses a limited set of ASCII characters for node identifiers. But it
allows us to quote any identifier. We'll just quote everything to be safe.

> quote    ::  String -> String
> quote n  =   "\"" ++ n ++ "\""

This program is a simple filter that accepts an \iptables{} dump as input and
outputs a Graphviz representation.

> main  ::  IO ()
> main  =   getContents >>= graphviz . parseChains

|parseChains| applies the Parsec parser we've built up until this point to the
string it receives (an \iptables{} dump). If there are any errors, it prints
them on stderr (using Parsec's error message).

TODO: How can we use lazy evaluation to graph as we parse?

> parseChains    ::  String -> [Chain]
> parseChains x  =   case (parse chains "" x) of
>                      Left err  -> error (show err) >> []
>                      Right cs  -> cs

Since this is \verb!ingressgraph!, we only want to graph the {\sc input} chain.

> graphviz     ::  [Chain] -> IO ()
> graphviz cs  =   putStr "digraph ingressgraph {\n" >>
>                  case c of
>                    Just c'  -> graph c'
>                    Nothing  -> return ()
>                  >> putStr "}\n"
>     where c = find ((== "INPUT") . fst) cs

\end{document}