# TP OSINT / CTI

## A1 — Recherche de sous-domaines et analyse des certificats TLS

Nous avons recherché les sous-domaines associés à `pme-fictive.lizurey.fr` à l'aide des journaux de transparence des certificats TLS.

Le site crt.sh étant indisponible, nous avons utilisé l'alternative ctlogs.dev.

L'analyse des certificats a permis d'identifier les noms suivants :

| Nom DNS | Rôle possible |
|---|---|
| pme-fictive.lizurey.fr | Site principal |
| www.pme-fictive.lizurey.fr | Site web |
| mail.pme-fictive.lizurey.fr | Service de messagerie |
| extranet.pme-fictive.lizurey.fr | Portail extranet |

Les certificats consultés ont été délivrés par Let's Encrypt le 25 octobre 2026 et sont valables jusqu'au 23 janvier 2027.

Nous avons ensuite utilisé la commande `dig` pour vérifier la résolution DNS de ces noms. Les quatre noms pointent vers la même adresse IPv4 : **149.56.98.172**.

Nous avons également identifié les informations DNS suivantes :

- Serveur de messagerie (MX) : `mail.pme-fictive.lizurey.fr`
- Politique SPF : `v=spf1 mx -all`
- Serveurs DNS du domaine parent `lizurey.fr` : `ns1.amenworld.com` et `ns2.amenworld.com`

La politique SPF indique que seuls les serveurs désignés par les enregistrements MX sont autorisés à envoyer des emails pour ce domaine.

Enfin, nous avons essayé de consulter les archives de Wayback Machine pour rechercher d'anciens sous-domaines, mais cette recherche n'a pas donné de résultats exploitables.

**Conclusion :** cette étape nous a permis d'identifier plusieurs noms DNS et de recueillir des informations sur l'infrastructure publique de la PME. Cependant, nous n'avons pas pu confirmer l'existence d'anciens sous-domaines.

### Captures d'écran

**Figure 1 — Sous-domaines identifiés dans les certificats TLS**

[Insérer la capture ctlogs.dev montrant le champ SAN]

**Figure 2 — Résolution DNS des sous-domaines**

[Insérer la capture du terminal montrant les quatre adresses IP]

**Figure 3 — Enregistrements DNS MX, TXT et NS**

[Insérer la capture du terminal montrant les enregistrements DNS]


## A2 — Exposition des services

Nous avons utilisé Shodan pour analyser l'adresse IP `149.56.98.172`, identifiée lors de l'étape A1.

Cette adresse correspond à un serveur Linux hébergé chez OVH, à Montréal (Canada).

Shodan a identifié trois ports ouverts :

| Port | Service | Informations |
|---|---|---|
| 22/TCP | SSH | OpenSSH 10.0p2 (Debian) |
| 80/TCP | HTTP | Serveur Caddy, redirection vers HTTPS (308) |
| 443/TCP | HTTPS | Réponse HTTP 400, service identifié comme Ncat HTTP proxy |

Le port 22 permet l'administration distante du serveur. Le port 80 redirige les connexions vers HTTPS. Sur le port 443, Shodan a reçu une erreur HTTP 400, ce qui ne permet pas d'identifier précisément l'application.

Aucune CVE n'a été signalée dans les résultats Shodan consultés. Cela ne garantit pas l'absence de vulnérabilités.

**Hôte le plus intéressant :** l'adresse `149.56.98.172` concentre plusieurs services accessibles depuis Internet. Le sous-domaine `extranet.pme-fictive.lizurey.fr` mérite une attention particulière, car il pourrait correspondre à un portail réservé aux utilisateurs de l'organisation. Son fonctionnement reste toutefois à confirmer.

**Lien avec la Pyramid of Pain :** une adresse IP utilisée par un attaquant est relativement facile à remplacer. En revanche, bloquer les techniques qu'il utilise l'oblige à modifier sa manière d'opérer, ce qui est plus difficile. Il est donc important de sécuriser les services exposés et de surveiller les comportements suspects.

**Source :** https://www.shodan.io/host/149.56.98.172

### Captures d'écran

**Figure 4 — Informations générales du serveur**

[Insérer la capture Shodan montrant l'adresse IP, OVH, Montréal et Linux]

**Figure 5 — Services exposés**

[Insérer la capture Shodan montrant les ports 22, 80 et 443]

