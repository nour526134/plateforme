#!/usr/bin/env python3
"""Testeur Sigma pédagogique : applique une règle Sigma à des journaux JSON (une ligne = un événement)
et affiche vrais positifs, faux positifs et faux négatifs.

Usage : sigma-test.py regle.yml dossier_malveillant/ dossier_benin/
Convention : dans dossier_malveillant/, chaque fichier *.jsonl doit être détecté au moins une fois (sinon FN) ;
             dans dossier_benin/, toute détection est un FP.
Le moteur implémente le sous-ensemble usuel de Sigma : sélections avec modificateurs contains, startswith, endswith, all,
re, listes (OU), sélection donnée comme liste de maps (OU entre les maps), listes `keywords:` (liste de chaînes : match si
l'une d'elles apparaît dans n'importe quelle valeur de l'événement, insensible à la casse), conditions and / or / not /
1 of / all of. Verdict « acceptable » seulement si FP = 0, FN = 0 et TP > 0. Pour la conversion réelle vers un SIEM : sigma-cli.
Limite : pas d'agrégation (count() by …) — une rafale d'authentifications ne s'exprime pas en une sélection simple.
Depuis le conteneur osint-tools : sigma-test.py /work/rules/sigma/x.yml /work/data/logs/malveillant/ /work/data/logs/benin/
"""
import json
import re
import sys
from pathlib import Path

import yaml


def match_value(field_value, pattern, mods):
    if field_value is None:
        return False
    v = str(field_value)
    p = str(pattern)
    if "re" in mods:
        return re.search(p, v) is not None
    vl, pl = v.lower(), p.lower()
    if "contains" in mods:
        return pl in vl
    if "startswith" in mods:
        return vl.startswith(pl)
    if "endswith" in mods:
        return vl.endswith(pl)
    if "*" in pl:
        return re.fullmatch(re.escape(pl).replace("\\*", ".*"), vl) is not None
    return vl == pl


def flatten_values(obj):
    """Toutes les valeurs scalaires d'un événement (y compris imbriquées), en chaînes."""
    if isinstance(obj, dict):
        for v in obj.values():
            yield from flatten_values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from flatten_values(v)
    elif obj is not None:
        yield str(obj)


def match_keywords(keywords, event):
    """Sélection `keywords:` (liste de chaînes) : vrai si l'un des mots-clés apparaît dans une valeur de l'événement."""
    values = [v.lower() for v in flatten_values(event)]
    for kw in keywords:
        k = str(kw).lower()
        if "*" in k:
            rx = re.compile(re.escape(k).replace("\\*", ".*"))
            if any(rx.search(v) for v in values):
                return True
        elif any(k in v for v in values):
            return True
    return False


def match_selection(sel, event):
    if isinstance(sel, list):
        if all(isinstance(s, dict) for s in sel):   # liste de maps = OU entre les maps
            return any(match_selection(s, event) for s in sel)
        if all(not isinstance(s, (dict, list)) for s in sel):   # liste de chaînes = keywords
            return match_keywords(sel, event)
        return any(match_selection(s, event) if isinstance(s, (dict, list)) else match_keywords([s], event) for s in sel)
    if not isinstance(sel, dict):   # valeur scalaire isolée = mot-clé unique
        return match_keywords([sel], event)
    for key, pattern in sel.items():
        parts = key.split("|")
        field, mods = parts[0], parts[1:]
        val = event.get(field)
        patterns = pattern if isinstance(pattern, list) else [pattern]
        if "all" in mods:
            ok = all(match_value(val, p, mods) for p in patterns)
        else:
            ok = any(match_value(val, p, mods) for p in patterns)
        if not ok:
            return False
    return True


def eval_condition(cond, detection, event):
    cond = cond.strip()
    names = [k for k in detection if k != "condition"]

    def value(name):
        return match_selection(detection[name], event)

    m = re.fullmatch(r"(1|all) of (\S+)", cond)
    if m:
        quant, pat = m.groups()
        sel = [n for n in names if pat == "them" or re.fullmatch(pat.replace("*", ".*"), n)]
        return any(value(n) for n in sel) if quant == "1" else all(value(n) for n in sel)
    # parseur minimal : not / and / or, avec parenthèses simples
    tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|1 of \S+|all of \S+|\S+", cond)

    def parse_or(i):
        left, i = parse_and(i)
        while i < len(tokens) and tokens[i] == "or":
            right, i = parse_and(i + 1)
            left = left or right
        return left, i

    def parse_and(i):
        left, i = parse_not(i)
        while i < len(tokens) and tokens[i] == "and":
            right, i = parse_not(i + 1)
            left = left and right
        return left, i

    def parse_not(i):
        if tokens[i] == "not":
            v, i = parse_not(i + 1)
            return (not v), i
        if tokens[i] == "(":
            v, i = parse_or(i + 1)
            return v, i + 1
        t = tokens[i]
        if t.startswith("1 of") or t.startswith("all of"):
            return eval_condition(t, detection, event), i + 1
        return value(t), i + 1

    result, _ = parse_or(0)
    return result


def run(rule, folder):
    hits = {}
    p = Path(folder)
    for f in ([p] if p.is_file() else sorted(p.glob("*.jsonl"))):
        n = 0
        with f.open() as fh:
            for line in fh:
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if eval_condition(rule["detection"]["condition"], rule["detection"], ev):
                    n += 1
        hits[f.name] = n
    return hits


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    rule = yaml.safe_load(Path(sys.argv[1]).read_text())
    for k in ("title", "logsource", "detection"):
        if k not in rule:
            sys.exit(f"Règle invalide : champ '{k}' manquant")
    if "condition" not in rule["detection"]:
        sys.exit("Règle invalide : pas de condition")
    # Une condition qui cite une sélection absente faisait planter le testeur (règle générée par LLM, 3 novembre 2026).
    noms = [k for k in rule["detection"] if k != "condition"]
    for t in re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|1 of \S+|all of \S+|\S+", str(rule["detection"]["condition"])):
        if t not in ("(", ")", "and", "or", "not") and not re.match(r"(1|all) of ", t) and t not in noms:
            sys.exit(f"Règle invalide : la condition cite « {t} », qui n'est pas une sélection de detection "
                     f"(sélections définies : {', '.join(noms) or 'aucune'})")
    mal, ben = run(rule, sys.argv[2]), run(rule, sys.argv[3])
    tp = sum(1 for n in mal.values() if n > 0)
    fn = sum(1 for n in mal.values() if n == 0)
    fp = sum(ben.values())
    print(f"Règle : {rule['title']}  (tags : {', '.join(rule.get('tags', []))})")
    print(f"Fichiers malveillants détectés : {tp}/{len(mal)}   FN : {fn}")
    for f, n in mal.items():
        print(f"   {'OK ' if n else 'MISS'} {f} ({n} événements)")
    print(f"Faux positifs sur le corpus bénin : {fp} événement(s) dans {sum(1 for n in ben.values() if n)} fichier(s)")
    for f, n in ben.items():
        if n:
            print(f"   FP   {f} ({n})")
    reasons = []
    if tp == 0:
        reasons.append("aucun fichier malveillant détecté (TP = 0)")
    if fn > 0:
        reasons.append(f"{fn} fichier(s) malveillant(s) non détecté(s) (FN > 0) — passez un seul fichier si la règle ne vise qu'une technique")
    if fp > 0:
        reasons.append(f"{fp} faux positif(s) sur le corpus bénin")
    if not reasons:
        print("VERDICT : acceptable (FP = 0, FN = 0, TP > 0)")
    else:
        print("VERDICT : à retravailler — " + " ; ".join(reasons))
