{
  description = "Visualize Your iptables Firewall";

  inputs.nixpkgs.url = github:NixOS/nixpkgs/nixos-20.03;

  outputs = {self, nixpkgs}: {
    defaultPackage.x86_64-linux =
      with import nixpkgs { system = "x86_64-linux"; };
      pkgs.haskellPackages.callPackage ./default.nix {};
    devShell.x86_64-linux =
      with import nixpkgs { system = "x86_64-linux"; };
      (pkgs.haskellPackages.callPackage ./default.nix {}).env;
  };
}
