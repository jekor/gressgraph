# gressgraph - Visualize Your Firewall

Visualize your firewall by graphing its rules.

Warning: This was only tested on small firewall rulesets.

## Requirements

* [Graphviz](http://www.graphviz.org/)
* iptables

If compiling from source:

* GHC     (>= 6.8.2)
* lhs2TeX (>= 1.11)
* GNU Make


For Ubuntu Server 16.04 run the following to install prerequisites

```
$ sudo apt install iptables graphviz make lhs2tex ghc libghc-parsec3-dev
```


## Usage

```ShellSession
$ iptables -L -vx | gressgraph > iptables.twopi
$ twopi -Tsvg iptables.twopi > iptables.svg
```

See the source for more detailed documentation, including a description of
how the program was written.

Note: There are no commandline options. Also, I've only tested the program
on my own simple iptables ruleset. It's likely that it will fail to parse your
rules.

## Building

```ShellSession
$ make
$ make test
```

If you didn't receive gressgraph.pdf:

```ShellSession
$ make doc
```

## Troubleshooting

### The program hangs after outputting `"// Interfaces"`.

gressgraph is waiting for input. Make sure you've sent it something on its
stdin (it does not take a file as a commandline argument).

# Building

I build gressgraph with [Nix](http://nixos.org/nix/) to try to ensure reproducible builds:

```
nix-build dev.nix
```

`default.nix` is for inclusion in a top-level file (such as `all-packages.nix`). `dev.nix` builds gressgraph with a fixed version of nixpkgs, providing stability at the cost of inflating the nix store.
