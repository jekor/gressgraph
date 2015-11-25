let
  _nixpkgs = import <nixpkgs> { };
in
{ nixpkgs ? _nixpkgs.fetchgit {
    url = "https://github.com/NixOS/nixpkgs.git";
    rev = "d53213677dc414f7c0464dd09c8530c22a4d45b6";
    sha256 = "211e649dc6dd850b8d5fff27f6645c10dc8b498a6586e2368bc7866b464d70aa";
  }
}:
let
  pkgs = if nixpkgs == null then _nixpkgs else import nixpkgs { };
in
  pkgs.haskellPackages.callPackage ./default.nix { }
