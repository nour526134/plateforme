#!/usr/bin/env python3
"""Exporte un événement MISP en bundle STIX 2.1 prêt à importer dans l'OpenCTI mutualisé (TP 4, partie B).

Usage : misp-vers-opencti.py <id de l'événement MISP> <numéro de groupe>
        ex. : misp-vers-opencti.py 1782 07   ->   out/opencti-groupe07-evenement1782.json

Ce que le script retire ou renomme, et pourquoi (constaté le 3 novembre 2026, OpenCTI 6.9.29, MISP 2.5.50) :
- les objets marking-definition : MISP joint la définition de TLP:GREEN, etc. ; OpenCTI refuse qu'un compte
  sans droit d'administration la recrée, même identique. Les références (object_marking_refs) restent :
  OpenCTI connaît déjà ces marquages TLP sous les mêmes identifiants ;
- les phases de kill chain « misp-category » : MISP range chaque indicateur dans une pseudo kill chain qui
  reprend sa catégorie (Network activity, Payload delivery…) ; la créer est aussi réservé aux administrateurs,
  et ce n'est pas une vraie kill chain ;
- l'organisation auteure est renommée « Groupe NN (IT320) » : tous les MISP du module s'appellent
  GroupeXX-IT320 par défaut, et OpenCTI fusionnerait les dix groupes en un seul auteur ;
- le conteneur (report ou grouping) est préfixé « Groupe NN — » : sinon les dix événements « Honeypot Cowrie »
  du même jour se fondraient en un seul conteneur ;
- les objets network-traffic (MISP en crée un par attribut ip-src ou ip-dst) sont remplacés par l'adresse IP
  qu'ils référencent : quand l'adresse existe déjà dans OpenCTI (un autre groupe l'a importée avant vous),
  OpenCTI 6.9.29 refuse de les recréer (« Cant add another relation on single ref »), et le conteneur qui les
  cite échoue à son tour. On perd le port et le sens de la connexion, pas l'adresse.
"""
import json
import sys
from collections import Counter
from pathlib import Path

from misp_client import Misp

if len(sys.argv) != 3 or not sys.argv[1].isdigit() or not sys.argv[2].isdigit():
    sys.exit(__doc__)
event_id, groupe = sys.argv[1], f"{int(sys.argv[2]):02d}"

misp = Misp()
r = misp.s.post(f"{misp.url}/events/restSearch",
                json={"eventid": event_id, "returnFormat": "stix2", "stix-version": "2.1"}, timeout=120)
r.raise_for_status()
bundle = r.json()
objects = bundle.get("objects", [])
if not objects:
    sys.exit(f"L'export STIX de l'événement {event_id} est vide. Si l'événement porte une galaxie, c'est le défaut "
             "connu de MISP 2.5.50 (séance 2) : exportez un événement sans galaxie, ou retirez-la avant l'export.")

retires, kc = Counter(), 0
# network-traffic -> adresses qu'il référence (src_ref, dst_ref)
trafic = {o["id"]: [o[k] for k in ("src_ref", "dst_ref") if k in o] for o in objects if o["type"] == "network-traffic"}


def sans_trafic(refs):
    vus = []
    for ref in refs:
        for r in trafic.get(ref, [ref]):
            if r not in vus:
                vus.append(r)
    return vus


sortie = []
for o in objects:
    if o["type"] == "marking-definition":
        retires[o.get("name", o["id"])] += 1
        continue
    if o["type"] == "network-traffic":
        retires["network-traffic"] += 1
        continue
    if "object_refs" in o:
        o["object_refs"] = sans_trafic(o["object_refs"])
    if o["type"] == "relationship":
        o["source_ref"], o["target_ref"] = sans_trafic([o["source_ref"]])[0], sans_trafic([o["target_ref"]])[0]
    if "kill_chain_phases" in o:
        garde = [p for p in o["kill_chain_phases"] if p.get("kill_chain_name") != "misp-category"]
        kc += len(o["kill_chain_phases"]) - len(garde)
        if garde:
            o["kill_chain_phases"] = garde
        else:
            del o["kill_chain_phases"]
    if o["type"] == "identity" and o.get("identity_class") == "organization":
        o["name"] = f"Groupe {groupe} (IT320)"
    if o["type"] in ("report", "grouping"):
        o["name"] = f"Groupe {groupe} — {o.get('name', '')}"
    sortie.append(o)
bundle["objects"] = sortie

dest = Path("/work/out") if Path("/work/out").is_dir() else Path("out")
fichier = dest / f"opencti-groupe{groupe}-evenement{event_id}.json"
fichier.write_text(json.dumps(bundle, ensure_ascii=False, indent=1), encoding="utf-8")

print(f"Écrit : out/{fichier.name} ({len(sortie)} objets)")
print("Par type :", ", ".join(f"{t} {n}" for t, n in Counter(o["type"] for o in sortie).most_common()))
print("Retiré :", ", ".join(f"{k} {v}" for k, v in retires.items()) or "rien", f"; phases misp-category : {kc}")
conteneurs = [o["name"] for o in sortie if o["type"] in ("report", "grouping")]
print("Conteneur :", conteneurs[0] if conteneurs else "aucun")
