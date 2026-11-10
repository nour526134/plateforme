# Sorties d'exercice — TP 3 (plan B si Ollama est indisponible)

Même principe que pour le TP 2 : sorties rédigées pour le TP, avec des défauts illustratifs. Ce ne sont pas des sorties vérifiées d'un modèle, et les défauts du direct sont différents. À tester et à corriger comme si elles sortaient du workflow.

- `silex7-loaderx-ia.yar` : compile ; mais `$s3` (`Mozilla/5.0`) est trop générique et `2 of them` peut matcher des fichiers sains qui
  contiennent « LoaderX » et un User-Agent ; `$s2` reprend le mutex avec un double antislash à vérifier. Tester sur `data/samples/` et `data/corpus-sain/`.
- `silex7-powershell-ia.yml` : correcte dans l'esprit ; `-enc` en `contains` attrape aussi `-encoding` (faux positifs possibles) ; pas de
  filtre sur `WindowStyle hidden` pourtant décrit dans le rapport. Tester avec `sigma-test.py` sur `data/logs/`.
- `attack-ia.json` : 8 techniques justes, **T1003.001 inféré** (non décrit dans le rapport) et **T1071.001** (dans la liste de candidats,
  absent de l'annexe du rapport ; défendable ou non selon la lecture des requêtes HTTP de LoaderX) : précision 8/10, rappel 8/8 par
  rapport à la référence du rapport. `hors_liste` est vide : toutes les techniques proposées figurent dans `candidats-attack.txt`.

Les noms de fichiers diffèrent de ceux qu'écrit le workflow (`silex-7-ia.yar`, `silex-7-ia.yml`) : dans les commandes de B2, remplacez
`out/ia/silex-7-ia.yar` par `out/ia/silex7-loaderx-ia.yar` et `out/ia/silex-7-ia.yml` par `out/ia/silex7-powershell-ia.yml`.

Copier ces fichiers dans `out/ia/` pour dérouler la partie B du TP 3 sans LLM.
