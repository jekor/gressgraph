{ mkDerivation, base, parsec, stdenv, lhs2tex, graphviz }:
mkDerivation {
  pname = "gressgraph";
  version = "0.2.1";
  src = ./.;
  isLibrary = false;
  isExecutable = true;
  buildDepends = [ lhs2tex graphviz ];
  executableHaskellDepends = [ base parsec ];
  homepage = "http://jekor.com/gressgraph";
  description = "Visualize Your iptables Firewall";
  license = "MIT";
}
