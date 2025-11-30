{
  stdenvNoCC,
  asciidoctor,
  self,
}:
stdenvNoCC.mkDerivation rec {
  name = "agenix-doc";
  src = ../doc;
  nativeBuildInputs = [ asciidoctor ];
  phases = [ "buildPhase" ];
  buildPhase = ''
    mkdir -p $out
    asciidoctor -o $out/index.html $src/readme.adoc
  '';
}
