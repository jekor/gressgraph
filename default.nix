{ mkDerivation, base, parsec, stdenv }:
mkDerivation {
  pname = "gressgraph";
  version = "0.2.1";
  src = ./.;
  isLibrary = false;
  isExecutable = true;
  executableHaskellDepends = [ base parsec ];
  homepage = "http://jekor.com/gressgraph";
  description = "Visualize Your iptables Firewall";
  license = "MIT";
}
