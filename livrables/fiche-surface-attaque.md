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

## A3 — Personnes et adresses

Nous avons recherché les personnes et adresses mail de la PME à partir de trois sources : l'outil theHarvester, la consultation manuelle du site web, et la fuite de données simulée fournie (`data/fuite-simulee.txt`).

**theHarvester** (sources crtsh, duckduckgo, hackertarget) : aucune adresse mail ni personne trouvée. L'outil confirme deux hôtes, extranet.pme-fictive.lizurey.fr et mail.pme-fictive.lizurey.fr, tous deux sur 149.56.98.172, ce qui recoupe les résultats d'A1. L'absence d'adresses s'explique par la jeunesse du domaine (créé le 25/10/2026), encore peu indexé par les moteurs : seule la consultation manuelle du site révèle les adresses. La source `bing` n'est plus supportée par la version 4.11.1 de l'outil.

**Site web** (pages Équipe et Recrutement) : quatre adresses sont publiées.

| Adresse (anonymisée) | Fonction | Source |
|---|---|---|
| m.d***@pme-fictive.lizurey.fr | Directrice générale | https://www.pme-fictive.lizurey.fr/equipe.html |
| t.l***@pme-fictive.lizurey.fr | Responsable informatique | /equipe.html et /recrutement.html |
| k.b***@pme-fictive.lizurey.fr | Responsable comptable et achats | /equipe.html |
| contact@pme-fictive.lizurey.fr | Adresse générique | /equipe.html, pied de page |

**Convention de nommage :** `prenom.nom@pme-fictive.lizurey.fr`. Elle permet de deviner l'adresse de n'importe lequel des 120 salariés à partir de son nom.

**Fuite simulée :** deux adresses y apparaissent, chacune associée à une empreinte de mot de passe (40 caractères hexadécimaux, format compatible avec SHA-1) :
- m.d***@ (directrice générale)
- t.l***@ (responsable informatique)

Conformément à la charte, aucune empreinte n'a été cassée et aucun identifiant n'a été testé.

**Pourquoi c'est un risque :**
- Le **responsable informatique** a probablement des droits d'administration : son compte est la cible la plus critique.
- La **directrice générale** est une cible pour l'**arnaque au président** (faux virements).
- Le **responsable comptable et achats**, absent de la fuite, reste une cible de phishing financier (fausses factures).
- La page Recrutement révèle les technologies utilisées (Active Directory, messagerie Zimbra, pare-feu FortiGate 60F, accès distant RDP, sauvegardes Veeam), ce qui permet à un attaquant de cibler son phishing et ses tentatives d'accès.

**Recommandations :**
1. Réinitialiser immédiatement les mots de passe des deux comptes présents dans la fuite, sur tous les services (AD, Zimbra, extranet, VPN/RDP).
2. Activer l'authentification multifacteur, en priorité sur l'accès distant RDP, la messagerie et l'extranet.
3. Remplacer les adresses nominatives du site par des adresses génériques (`direction@`, `rh@`, `recrutement@`).
4. Sensibiliser la direction et la comptabilité à l'arnaque au président et aux fausses factures.
5. Surveiller le domaine sur Have I Been Pwned (notification de nouvelles fuites).

### Captures d'écran

**Figure 6 — Page Équipe du site (adresses nominatives)**

[Insérer la capture de /equipe.html]

**Figure 7 — Offre d'emploi (technologies et contact)**

[Insérer la capture de /recrutement.html]

**Figure 8 — Sortie de theHarvester**

[Insérer la capture du terminal]

**Figure 9 — Adresses présentes dans la fuite simulée**

[Insérer la capture du grep, en masquant les empreintes]

## A4 — Code et documents

### Dépôt GitHub

Une recherche GitHub nous a permis d'identifier le dépôt public `github.com/pme-fictive/outils-extranet`, qui référence l'extranet `https://extranet.pme-fictive.lizurey.fr/`. Il contient un seul commit (`a80603d`, « initial commit »), créé par T. L*** (responsable informatique). Le README indique « Ne pas diffuser » alors que le dépôt est public.

Le dépôt contient trois fichiers : `README.md`, `config.example.ini` et `export_erp.py`.

**Secrets exposés en clair** (masqués ici) :

| Élément | Valeur (masquée) | Fichier |
|---|---|---|
| Clé API de production | `pmf_live_7f3a***` | export_erp.py |
| Compte base de données | `erp_export` / `Export2***` | export_erp.py |

**Informations d'architecture révélées :**
- API d'import sur l'extranet : `/api/v1/import` ;
- base de données interne sur `10.20.0.15` (plan d'adressage privé 10.20.0.0) ;
- ERP Sage (confirme l'offre d'emploi) ;
- accès RDP prévu sur `extranet.pme-fictive.lizurey.fr:3389` (non visible dans Shodan : port filtré ou non exposé, non confirmé) ;
- envoi de mails via `mail.pme-fictive.lizurey.fr:587`.

**Exploitabilité (non testée, conformément à la charte) :**
- La clé API « live » vise un service accessible depuis Internet : elle est vraisemblablement exploitable pour injecter ou modifier des données dans l'extranet clients.
- Le mot de passe de la base n'est pas utilisable directement (IP privée), mais il le devient après une première intrusion, et son format faible (mot + année + caractère spécial) laisse craindre une réutilisation sur d'autres comptes.

**Recommandations :**
1. Révoquer immédiatement la clé API et changer le mot de passe du compte `erp_export`.
2. Rendre le dépôt privé, puis le purger (le secret reste dans l'historique Git et peut avoir déjà été copié).
3. Stocker les secrets hors du code (variables d'environnement, coffre-fort de secrets) et activer la détection de secrets (GitHub secret scanning, gitleaks).
4. Ne pas exposer RDP sur Internet : le placer derrière le VPN FortiGate avec authentification multifacteur.

### Moteurs de recherche (dorks)

Nous avons lancé les trois recherches suivantes dans Google le 01/11/2026 :

| Requête | Objectif | Résultat |
|---|---|---|
| `site:pme-fictive.lizurey.fr filetype:pdf` | Documents PDF indexés | Aucun résultat |
| `"pme-fictive.lizurey.fr" password` | Pages mentionnant un mot de passe | Aucun résultat |
| `site:pme-fictive.lizurey.fr intitle:"index of"` | Répertoires ouverts | Aucun résultat |

Le domaine, créé le 25/10/2026, n'est pas encore indexé par les moteurs de recherche. L'absence de résultat ne signifie donc pas l'absence d'exposition : la plaquette PDF est bien accessible sur le site, et les répertoires ouverts éventuels (notamment sur dev-old) devront être vérifiés par une observation directe (partie A7).

### Métadonnées de la plaquette PDF

La plaquette commerciale (`https://www.pme-fictive.lizurey.fr/plaquette.pdf`) a été analysée avec exiftool 12.76.

| Champ | Valeur | Ce qu'elle révèle |
|---|---|---|
| Author | `k.b***` | Login Windows interne d'un salarié (responsable comptable et achats) : format des identifiants Active Directory `initiale.nom`, distinct du format des adresses mail (`prenom.nom@`) |
| Subject | `D:\Partage\Communication\plaquette-2023-v3.indd` | Chemin d'un partage réseau interne (dossier Communication) |
| Creator | Adobe InDesign 18.5 (Windows) | Poste de travail sous Windows, version logicielle précise |
| Producer | Adobe PDF Library 17.0 | Moteur de génération du PDF |
| Create / Modify Date | 11/04/2023 et 12/04/2023 (UTC+02:00) | Document de 2023 jamais mis à jour, produit en France |

**Pourquoi c'est un risque :** combiné aux noms publiés sur la page Équipe, le format `initiale.nom` permet de construire une liste d'identifiants Active Directory valides, utilisable pour des attaques par pulvérisation de mots de passe (password spraying) sur les services exposés (extranet, messagerie, RDP).

**Recommandation :** nettoyer les métadonnées de tous les documents publiés (`exiftool -all=`, ou option « supprimer les informations personnelles » à l'export), et intégrer cette étape dans la procédure de publication.

### Synthèse A4

Le dépôt GitHub est la fuite la plus grave de la PME : il expose une clé API de production et des identifiants en clair, publiés par le responsable informatique dont le mot de passe figure déjà dans la fuite (A3). Les métadonnées de la plaquette complètent le tableau en révélant le format des comptes internes et un partage réseau. Un attaquant dispose ainsi de noms, de formats d'identifiants, d'un secret vraisemblablement valide et d'une cartographie partielle du réseau interne, sans avoir touché la cible.

### Captures d'écran

**Figure 10 — Dépôt GitHub public de la PME**

[Insérer la capture de github.com/pme-fictive/outils-extranet]

**Figure 11 — Secrets en clair dans export_erp.py**

[Insérer la capture du fichier, en masquant la clé API et le mot de passe]

**Figure 12 — Fichier config.example.ini**

[Insérer la capture du fichier]

**Figure 13 — Métadonnées de la plaquette (exiftool)**

[Insérer la capture du terminal]