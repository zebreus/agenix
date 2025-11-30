{
  stdenvNoCC,
  asciidoctor,
  self,
}:
stdenvNoCC.mkDerivation rec {
  name = "agenix-doc";
  src = ../.;
  nativeBuildInputs = [ asciidoctor ];
  phases = [ "buildPhase" ];
  buildPhase = ''
    mkdir -p $out
    asciidoctor -o $out/index.html $src/readme.adoc
    asciidoctor -o $out/cli.html $src/pkgs/readme.adoc
    asciidoctor -o $out/modules.html $src/modules/readme.adoc
    asciidoctor -o $out/secrets-nix.html $src/pkgs/secrets-nix.adoc
    asciidoctor -b manpage -o $out/agenix.1 $src/pkgs/readme.adoc
    asciidoctor -b manpage -o $out/secrets.nix.5 $src/pkgs/secrets-nix.adoc
  '';
}
