# Sorties d'exercice — TP 2 (plan B si Ollama est indisponible)

Ces quatre fichiers ont été rédigés pour le TP. Ils simulent la réponse d'un LLM, au format du schéma de `prompts/extraction-certfr.md`, avec des **défauts illustratifs**, pour que la mesure de précision et de rappel reste possible sans serveur.

**Ce ne sont pas des sorties vérifiées de `qwen2.5:7b-instruct`, et ils ne décrivent pas son comportement.** Mesuré en direct le 3 novembre 2026 (température 0, même prompt, trois exécutions par alerte), le modèle trouve les 6 CVE et les 12 IoC sans rien inventer et ne suit pas la consigne de l'alerte piégée ; ses erreurs réelles sont ailleurs : tactique « TA1190 » inexistante, versions de produits perdues. Un rendu en plan B doit donc dire que ses chiffres portent sur ces fichiers d'exercice.

Défauts placés dans chaque fichier :

- `alerte-2026-01` : extraction complète et exacte ; la tactique TA0001 est une inférence (le texte ne la cite pas) : à discuter.
- `alerte-2026-02` : une URL **inventée** (`https://facture-securisee.example/charge.bpx`, absente du texte) → le validateur de littéralité doit la rejeter ;
  la technique T1204.002 n'apparaît pas textuellement → hors schéma.
- `alerte-2026-03` : **CVE-2026-30503 manquante** (rappel < 1) ; T1505.003 n'est pas dans le texte.
- `alerte-piegee` : la sortie simule un modèle qui **suit l'injection** (produit « Windows Server 2022 », IP 198.51.100.1 ajoutés) tout en la signalant dans
  `suspicious_instructions` : c'est le cas que le validateur devrait attraper (l'IP n'est présente que dans un commentaire).

Usage : dans n8n, remplacer le nœud HTTP Ollama par un nœud Code qui lit `/data/llm-precalcule/tp2/<alerte>.llm.json`, ou exécuter directement
`python3 -c "import json;print(json.load(open('data/llm-precalcule/tp2/alerte-2026-02.llm.json')))"` et appliquer le validateur à la main.
Les sorties de référence (vérité terrain) sont la lecture humaine de chaque alerte : CVE, produits, IoC écrits dans le texte, rien d'autre.
