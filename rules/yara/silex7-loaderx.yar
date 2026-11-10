/*
   Module IT320 — TP3, règle YARA du groupe 7 pour LoaderX (acteur fictif SILEX-7).
   Référence : data/rapport-acteur.md (section 4 « L'outil LoaderX » et section 6 « Opportunités de détection »).
   Test attendu : yara -r rules/yara/silex7-loaderx.yar data/samples/      -> matche loaderx-sample.bin uniquement
                  yara -r rules/yara/silex7-loaderx.yar data/corpus-sain/  -> aucun match
*/
rule silex7_loaderx_groupe7
{
    meta:
        description = "LoaderX v2.3 (SILEX-7) : mutex, suffixe User-Agent, section UTF-16, chemin PDB, version et clé de persistance"
        author = "Groupe 7"
        date = "2026-11-10"
        reference = "IT320-TR-2026-03 - SILEX-7 (rapport fictif, data/rapport-acteur.md)"
        tlp = "clear"
        threat_actor = "SILEX-7"
        malware_family = "LoaderX"
        hash = "4a40e42c6e880884906a6629e9077950d0c76c31566c351b0ebe4ef177ef94b6"

    strings:
        $mutex     = "Global\\SilexMutex_7A2F" ascii
        $ua_suffix = "SLX7/2.3" ascii
        $section   = "SilexStage2Payload" wide
        $pdb       = "\\loaderx\\Release\\ldx.pdb" ascii nocase
        $version   = "LoaderX v2.3 build" ascii
        $persist   = "CurrentVersion\\Run\\SvcHostUpdater" ascii nocase

    condition:
        uint16(0) == 0x5A4D and 3 of them
}