# GUIDE DE RÉVISION — PROJET DE STAGE
## Sécurisation et supervision d'un environnement ICS/SCADA avec GRFICSv3, Wazuh SIEM et Suricata IDS
### EMSI — ENNOUKRA Abdelghafour / AZARG Hafssa — 2025-2026

---

## RÉSUMÉ DES SCÉNARIOS

### Scénario 1 — Lecture non autorisée de registres Modbus
| Élément | Valeur |
|---|---|
| Technique MITRE | T0801 — Monitor Process State |
| Outil | pymodbus (Python) |
| Cible | PLC OpenPLC — 192.168.95.2:502 |
| Action | Lecture FC3 (Read Holding Registers) des registres du PLC |
| Impact | Fuite d'informations sur l'état du procédé |
| Détection | Suricata Quickdraw (SID 2250008) |
| Contre-mesure | Alertes Wazuh (règle 86601) |

---

### Scénario 2 — Écriture non autorisée sur les registres Modbus
| Élément | Valeur |
|---|---|
| Technique MITRE | T0836 — Modify Parameter + T0855 — Unauthorized Command |
| Outil | Script Python + pymodbus |
| Cible | PLC OpenPLC — registres Modbus (FC16) |
| Action | Écriture forcée d'une valeur sur un registre contrôlant Feed2 (45.8%) |
| Impact | Modification du procédé industriel (perturbation Tennessee Eastman) |
| Détection | Suricata Quickdraw (SID 9000001) → Wazuh règle 100200 |
| Contre-mesure SOAR | Active-Response → modbus-block.sh → iptables DROP (INPUT + FORWARD) |
| Délai de blocage | Quasi-immédiat (alerte unique suffisante) |

---

### Scénario 3 — Déni de service applicatif Modbus
| Élément | Valeur |
|---|---|
| Technique MITRE | T0814 — Denial of Service |
| Outil | Script Python flood.py + pymodbus |
| Cible | PLC OpenPLC — port 502 |
| Action | 300 requêtes FC3 consécutives sans délai |
| Impact | Saturation du service Modbus, dégradation de la supervision |
| Alertes Suricata | 481 × SID 2250008 + 6 × SID 1111012 = 487 alertes |
| Dashboard Wazuh | 7 236 occurrences règle 86601 |
| Incidents rencontrés | 4 incidents résolus (Suricata non démarré, bruit de fond, fichier eve.json corrompu, offset d'indexation obsolète) |
| Contre-mesure SOAR | Règle 100300 (5 alertes/30s) → modbus-dos-block.sh → iptables DROP |
| Délai de blocage | Quelques secondes |

---

### Scénario 4 — Brute force HTTP sur l'interface ScadaLTS
| Élément | Valeur |
|---|---|
| Technique MITRE | T1110 — Brute Force + T1078.001 — Default Accounts |
| Outil | Hydra (http-post-form) |
| Cible | HMI ScadaLTS — 192.168.90.107:8080 / POST /login.htm |
| Critère succès Hydra | S=views.shtm |
| Volume | 25 combinaisons (5 users × 5 passwords) |
| Résultat Hydra | 5 couples "valides" annoncés |
| Résultat réel | 1 seul valide (admin:admin) — taux FP Hydra : 80% |
| Cause des FP | Réutilisation des cookies de session Tomcat par Hydra |
| Angle mort initial | Aucune règle native sur les logs HTTP ScadaLTS |
| Décodeur utilisé | web-accesslog (natif Wazuh, règle parente 31108) |
| Règles créées | 100100 (niveau 5, détection unitaire) + 100101 (niveau 10, corrélation 8 req/60s, MITRE T1110) |
| Dashboard Wazuh | 12 024 événements |
| Contre-mesure SOAR | Active-Response → firewall-drop → iptables DROP (timeout 600s) |
| Délai de blocage | < 1 minute |

---

## QUESTIONS PROBABLES DU JURY

### Sur la plateforme GRFICSv3

**Q : Qu'est-ce que GRFICSv3 et pourquoi l'avoir choisi ?**
> GRFICSv3 (Graphical Realistic Industrial Control System) est une plateforme open source développée par Fortiphyd Logic qui simule un environnement ICS complet via Docker. Elle inclut un PLC (OpenPLC), une interface SCADA/HMI (ScadaLTS), un routeur, un historien et un procédé chimique (Tennessee Eastman Process). Le choix s'impose car c'est une des rares plateformes permettant de reproduire fidèlement une architecture ICS réelle (segmentation DMZ/ICS, protocole Modbus réel) sans matériel physique coûteux.

**Q : Qu'est-ce que le Tennessee Eastman Process (TEP) ?**
> Le TEP est un procédé chimique industriel de référence, créé par Downs et Vogel (1993), utilisé comme banc d'essai standard pour les systèmes de contrôle de procédés. Dans GRFICSv3, il simule une réaction chimique avec des réacteurs, des séparateurs, des compresseurs et des vannes, contrôlés par le PLC via Modbus.

**Q : Expliquez l'architecture réseau de votre plateforme.**
> Deux segments réseaux distincts :
> - **DMZ (192.168.90.0/24)** : machine Kali (attaquant), HMI ScadaLTS, routeur/IDS, station d'ingénierie
> - **ICS (192.168.95.0/24)** : PLC OpenPLC (192.168.95.2)
> Le routeur fait office de passerelle et point d'inspection Suricata entre les deux zones, conformément au modèle Purdue (niveaux 3.5 / DMZ industrielle).

**Q : Pourquoi utiliser Docker pour simuler un environnement ICS ?**
> Docker permet d'isoler chaque composant dans son propre conteneur (PLC, HMI, routeur, attaquant), de reproduire la segmentation réseau via des réseaux Docker dédiés, et de déployer l'ensemble rapidement et de manière reproductible via Docker Compose. La contrepartie est que les conteneurs partagent le noyau hôte, ce qui simplifie certains aspects (pas de gestion de firmware physique) mais éloigne légèrement du comportement d'un automate physique réel.

---

### Sur le protocole Modbus

**Q : Expliquez le protocole Modbus TCP et sa principale vulnérabilité.**
> Modbus TCP est un protocole industriel de niveau applicatif (couche 7) transporté sur TCP/IP, standardisé par Modbus-IDA. Il utilise un modèle maître/esclave : le maître (HMI) envoie des requêtes au serveur (PLC). Les codes fonction principaux sont FC1 (lecture bobines), FC3 (lecture registres holding), FC16 (écriture registres multiples). Sa vulnérabilité fondamentale : **aucune authentification native**. Tout hôte ayant accès au port 502 peut lire ou écrire des registres sans présenter d'identifiant. C'est une conception héritée des années 1970 pour des réseaux industriels physiquement isolés.

**Q : Qu'est-ce qu'un registre Holding et un code fonction FC3/FC16 ?**
> Les **Holding Registers** (registres de maintien, adresses 40001–49999) sont des zones mémoire 16 bits en lecture/écriture du PLC, utilisées pour stocker des consignes et des valeurs de procédé. **FC3** (Read Holding Registers) lit un bloc de registres. **FC16** (Write Multiple Registers) écrit plusieurs registres en une seule requête — c'est le vecteur utilisé dans le scénario 2 pour modifier la consigne Feed2.

---

### Sur Suricata

**Q : Comment Suricata est-il positionné dans votre architecture et pourquoi ?**
> Suricata est déployé sur le conteneur **router**, en écoute sur l'interface **eth1** (côté DMZ). Ce positionnement est stratégique : il intercepte **tout le trafic** entre le réseau DMZ (attaquant) et le réseau ICS (PLC), ce qui lui permet d'inspecter chaque requête Modbus avant qu'elle n'atteigne le PLC. Un positionnement sur le PLC lui-même serait insuffisant car il manquerait le trafic de transit.

**Q : Qu'est-ce que le ruleset Quickdraw ?**
> Quickdraw est un ensemble de règles Suricata développées par Digital Bond, spécialement conçues pour les protocoles industriels (Modbus, DNP3, EtherNet/IP). Pour Modbus, les règles principales sont :
> - **SID 2250008** : SURICATA Modbus Data mismatch — anomalie générique de cohérence des données Modbus
> - **SID 1111012** : SCADA_IDS Modbus TCP Incorrect Packet Length, Possible DOS Attack — qualification d'un flood Modbus
> - **SID 9000001** : Modbus Write — détection d'écriture FC16

**Q : Qu'est-ce que le fichier eve.json ?**
> eve.json est le fichier de sortie principal de Suricata au format JSON structuré (Extensible Event Format). Chaque événement (alerte, connexion réseau, protocole applicatif décodé) y est enregistré avec des champs standardisés : timestamp, src_ip, dest_ip, proto, alert.signature_id, alert.category, etc. L'agent Wazuh du routeur lit ce fichier en continu et transmet les événements au manager pour corrélation.

---

### Sur Wazuh

**Q : Expliquez l'architecture Wazuh (agent / manager / dashboard).**
> - **Agent Wazuh** : processus léger déployé sur chaque hôte surveillé (conteneur router, HMI, EWS). Il collecte les logs locaux (eve.json, access_log Tomcat, syslog) et les transmet chiffrés au manager via le port 1514.
> - **Manager Wazuh** : cœur de la plateforme. Il reçoit les événements, applique les décodeurs pour les parser, puis évalue les règles de détection/corrélation. Il gère aussi l'active-response.
> - **Indexer** : moteur de stockage et d'indexation basé sur OpenSearch.
> - **Dashboard** : interface web de visualisation (Kibana-like), modules Threat Hunting, Vulnerability Detector, etc.

**Q : Comment fonctionnent les décodeurs et les règles Wazuh ?**
> Le pipeline de traitement d'un événement Wazuh comprend 3 phases :
> 1. **Pré-décodage** : extraction du timestamp, hostname, program_name
> 2. **Décodage** : un décodeur XML parse le message et extrait des champs nommés (srcip, url, id, etc.). Ex : le décodeur `web-accesslog` extrait srcip, url, protocol depuis le Common Log Format de Tomcat.
> 3. **Filtrage (règles)** : les règles sont évaluées hiérarchiquement. Une règle fille (`if_sid`) ne peut se déclencher que si sa règle parente a préalablement matché. La règle 100100 est enfant de la règle 31108 (Ignored URLs).

**Q : Expliquez la contrainte `<url>` vs `<field name="url">` dans les règles Wazuh.**
> Dans le moteur Wazuh, certains champs sont **statiques** (réservés) et ont leur propre balise XML dédiée : `<url>`, `<srcip>`, `<dstip>`, `<user>`, etc. Utiliser `<field name="url">login.htm</field>` provoque l'erreur *Field 'url' is static*. Il faut obligatoirement écrire `<url>login.htm</url>`.

**Q : Qu'est-ce qu'une règle de fréquence (frequency/timeframe) dans Wazuh ?**
> Une règle de corrélation temporelle : elle se déclenche quand une règle parente (`if_matched_sid`) est activée **N fois** (`frequency`) dans une fenêtre glissante de **T secondes** (`timeframe`) depuis la **même source** (`same_source_ip`). Ex : règle 100101 → 8 occurrences de 100100 en 60 secondes depuis la même IP = brute force détecté.

**Q : Comment fonctionne l'Active Response de Wazuh ?**
> Quand une règle-cible se déclenche, Wazuh invoque automatiquement un script déclaré dans `ossec.conf`. La configuration comprend :
> - `<command>` : déclaration du script et de son exécutable
> - `<active-response>` : liaison à une règle_id, définition du `location` (local = sur l'agent, server = sur le manager, all = partout) et du `timeout` (déblocage automatique)
> Le script reçoit en paramètre l'alerte JSON et extrait l'IP source pour insérer la règle `iptables`.

**Q : Qu'est-ce que wazuh-logtest et à quoi sert-il ?**
> `wazuh-logtest` est un outil en ligne de commande du manager Wazuh qui permet de tester le pipeline de décodage/filtrage sur une ligne de log donnée, sans générer de vraie alerte. Il affiche les 3 phases (pré-décodage, décodage, filtrage) et indique si une alerte serait générée. Utilisé pour valider les règles sans redémarrer le service.

---

### Sur iptables et le blocage réseau

**Q : Expliquez la différence entre les chaînes INPUT et FORWARD d'iptables.**
> - **INPUT** : filtre les paquets destinés à l'hôte local lui-même (ex : connexions SSH vers le routeur). Dans le contexte scénario 4, bloque les connexions entrantes depuis l'attaquant vers l'interface HMI.
> - **FORWARD** : filtre les paquets qui transitent à travers l'hôte (ex : trafic Kali → PLC via le routeur). Dans le contexte scénario 2 et 3, bloque le trafic Modbus de l'attaquant vers le PLC au niveau du routeur.
> Les deux chaînes sont bloquées simultanément pour garantir un isolement complet.

**Q : Pourquoi utiliser un timeout de 600 secondes pour le déblocage ?**
> Le timeout de 600 secondes (10 minutes) garantit la **réversibilité** de la contre-mesure : si l'alerte est un faux positif, le blocage se lève automatiquement sans intervention humaine. En environnement de production, ce paramètre doit être calibré selon la politique de sécurité (plus long pour les attaques confirmées, plus court pour limiter l'impact opérationnel).

---

### Sur la sécurité ICS et les normes

**Q : Qu'est-ce que le modèle Purdue ?**
> Le modèle Purdue Enterprise Reference Architecture (PERA, Williams 1994) est un modèle hiérarchique organisant les systèmes industriels en 5 niveaux : niveau 0 (capteurs/actionneurs), niveau 1 (PLC/automates), niveau 2 (supervision locale), niveau 3 (gestion de site), niveau 4 (réseaux d'entreprise). La DMZ industrielle (niveau 3.5) constitue le point de filtrage entre les mondes IT et OT.

**Q : Qu'est-ce que la norme IEC 62443 ?**
> IEC 62443 est la norme internationale de référence pour la cybersécurité des systèmes d'automatisation et de contrôle industriels (IACS). Elle définit des exigences de sécurité organisées en Security Levels (SL 1 à SL 4) et couvre l'ensemble du cycle de vie du système (conception, déploiement, maintenance). Elle préconise notamment la segmentation en zones et conduits (Zones & Conduits) et la défense en profondeur.

**Q : Qu'est-ce que MITRE ATT&CK for ICS ?**
> MITRE ATT&CK for ICS est un référentiel de connaissances sur les tactiques, techniques et procédures (TTP) utilisées par les attaquants ciblant les systèmes industriels. Il est organisé en tactiques (Initial Access, Execution, Persistence, Lateral Movement, Collection, Command and Control, Inhibit Response Function, Impair Process Control, Impact) et en techniques numérotées (T0xxx). Il complète MITRE ATT&CK Enterprise (T1xxx) pour le domaine OT/ICS.

**Q : Qu'est-ce que le SOAR ? Quels sont ses avantages en contexte ICS ?**
> SOAR (Security Orchestration, Automation and Response) désigne la capacité à automatiser la réponse à un incident de sécurité à partir d'une alerte SIEM. En contexte ICS, ses avantages sont majeurs : réduction du délai de réponse de minutes à secondes, disponibilité 24h/24 sans opérateur de garde, neutralisation de l'attaquant avant qu'il ne puisse répéter l'attaque, et réversibilité automatique de la contre-mesure.

---

### Questions pièges / de recul

**Q : Pourquoi Hydra a-t-il produit 80% de faux positifs dans le scénario 4 ?**
> Hydra réutilise les cookies de session HTTP entre ses requêtes successives. Tomcat peut conserver un contexte de session actif (issu de la connexion admin/admin testée en premier) et rediriger les requêtes suivantes vers /views.shtm même avec de mauvais identifiants, car la session est encore valide. Hydra interprète cette redirection comme un succès d'authentification. C'est pourquoi la validation croisée indépendante (requêtes isolées sans cookie) est indispensable.

**Q : Pourquoi n'y avait-il aucune alerte dans Wazuh au début du scénario 4 ?**
> Deux facteurs cumulés : (1) `<logall>no</logall>` dans ossec.conf — tout événement ne correspondant à aucun décodeur actif est silencieusement ignoré ; (2) Aucune règle native ne cible les tentatives d'authentification HTTP sur le format Common Log Format de Tomcat. La collecte fonctionnait parfaitement, mais sans règle de détection, les logs étaient reçus et écartés sans trace.

**Q : Pourquoi avoir choisi le décodeur natif web-accesslog plutôt d'en créer un custom ?**
> Après vérification via wazuh-logtest, le décodeur natif web-accesslog parsait correctement le format Common Log Format de Tomcat, extrayant srcip, url, protocol et id. Écrire un décodeur custom aurait été redondant et aurait compliqué la maintenance. La bonne pratique est de réutiliser les décodeurs existants et d'ajouter uniquement les règles manquantes.

**Q : Quelles sont les limites principales de votre plateforme ?**
> (1) Conteneurisation vs matériel physique : OpenPLC sur Docker ne reproduit pas exactement le timing d'un Siemens S7 ou Schneider Modicon ; (2) Topologie simplifiée (2 segments) vs une architecture industrielle réelle avec des centaines de nœuds et un trafic de fond dense ; (3) Couverture protocolaire limitée à Modbus TCP (pas de DNP3, IEC 61850, OPC-UA) ; (4) Détection uniquement par signatures statiques (seuils), pas de détection comportementale.

---

## CHOSES À RÉVISER EN DÉTAIL

### 1. Architecture technique — savoir expliquer au tableau

```
RÉSEAU DMZ (192.168.90.0/24)
├── Kali Linux (192.168.90.6) — attaquant
├── ScadaLTS/HMI (192.168.90.107:8080) — interface web
├── Router/IDS (eth0:192.168.90.x, eth1:192.168.95.x)
│   └── Suricata sur eth1
└── EWS (Engineering Workstation)

RÉSEAU ICS (192.168.95.0/24)
└── PLC OpenPLC (192.168.95.2:502) — Modbus TCP
```

### 2. Modbus — connaître par cœur

- **FC1** : Read Coils (bobines, 1 bit, R/W)
- **FC2** : Read Discrete Inputs (entrées, 1 bit, R)
- **FC3** : Read Holding Registers (registres, 16 bits, R/W) ← scénario 3 (flood)
- **FC4** : Read Input Registers (registres, 16 bits, R)
- **FC5** : Write Single Coil
- **FC6** : Write Single Register
- **FC16** : Write Multiple Registers ← scénario 2 (écriture malveillante)
- Pas d'authentification, pas de chiffrement, pas d'intégrité des données

### 3. Wazuh — pipeline de traitement complet

```
Log brut (eve.json / access_log)
    ↓
Phase 1 : Pré-décodage (timestamp, hostname, program_name)
    ↓
Phase 2 : Décodage (décodeur XML → champs nommés)
  - suricata → src_ip, dest_ip, signature_id, alert.category
  - web-accesslog → srcip, url, protocol, id (code HTTP)
    ↓
Phase 3 : Filtrage (règles hiérarchiques)
  - Règle parente (if_sid)
  - Règle fille (if_matched_sid + frequency + timeframe)
    ↓
Alerte générée → Active Response (si règle-cible)
    ↓
Script → iptables DROP
```

### 4. Règles Wazuh — syntaxe XML à maîtriser

```xml
<!-- Règle de détection unitaire -->
<rule id="100100" level="5">
  <if_sid>31108</if_sid>       <!-- parent obligatoire -->
  <url>login.htm</url>          <!-- balise statique (pas <field>) -->
  <description>...</description>
</rule>

<!-- Règle de corrélation temporelle -->
<rule id="100101" level="10" frequency="8" timeframe="60">
  <if_matched_sid>100100</if_matched_sid>
  <same_source_ip />
  <description>...</description>
  <mitre><id>T1110</id></mitre>
</rule>
```

### 5. Active Response — configuration ossec.conf

```xml
<command>
  <name>nom-commande</name>
  <executable>script.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
<active-response>
  <command>nom-commande</command>
  <location>local</location>   <!-- local / server / all -->
  <rules_id>100101</rules_id>  <!-- règle déclenchante -->
  <timeout>600</timeout>       <!-- déblocage auto en secondes -->
</active-response>
```

### 6. MITRE ATT&CK for ICS — techniques du projet

| Code | Technique | Scénario |
|---|---|---|
| T0801 | Monitor Process State | Scénario 1 |
| T0836 | Modify Parameter | Scénario 2 |
| T0855 | Unauthorized Command Message | Scénario 2 |
| T0814 | Denial of Service | Scénario 3 |
| T1110 | Brute Force | Scénario 4 |
| T1078.001 | Default Accounts | Scénario 4 |
| T0832 | Manipulation of View | Impact potentiel S4 |

### 7. Chaînes SOAR — à réciter pour chaque scénario

**Scénario 2 :**
Écriture FC16 → Suricata (SID 9000001) → eve.json → Agent Wazuh → Règle 100200 → Active-Response → modbus-block.sh → iptables DROP (router) → Attaquant bloqué

**Scénario 3 :**
Flood FC3 × 300 → Suricata (SID 2250008 + SID 1111012) → eve.json → Agent Wazuh → Règle 86601 → Règle 100300 (5/30s) → Active-Response → modbus-dos-block.sh → iptables DROP (router) → Attaquant bloqué

**Scénario 4 :**
Hydra POST /login.htm → localhost_access_log (Tomcat) → Agent Wazuh HMI → Décodeur web-accesslog → Règle 100100 (niveau 5) → Règle 100101 (8/60s, MITRE T1110) → Active-Response → firewall-drop → iptables DROP (HMI) → Attaquant bloqué

### 8. Normes — points clés

- **IEC 62443** : norme ICS, Zones & Conduits, Security Levels 1–4, cycle de vie
- **NIST SP 800-82** : guide gouvernemental US pour la sécurité ICS, Rev.2 (2015), Rev.3 (2023)
- **Modèle Purdue** : 5 niveaux (0=terrain, 1=PLC, 2=SCADA, 3=gestion site, 4=entreprise) + DMZ 3.5
- **CIA Triad en OT** : priorité inversée — Disponibilité > Intégrité > Confidentialité (vs IT : C > I > D)

### 9. Incidents résolus dans scénario 3 — détail

| # | Problème | Cause | Solution |
|---|---|---|---|
| 1 | Aucune alerte | Suricata non démarré sur eth1 | Lancement manuel `suricata -i eth1` |
| 2 | Alertes noyées | Pas de filtre sur l'IP source | Filtre sur 192.168.90.6 dans eve.json |
| 3 | eve.json corrompu | 2 instances Suricata écrivant simultanément | Arrêt instance redondante + réinitialisation |
| 4 | Alertes absentes du dashboard | Offset d'indexation obsolète (> taille réelle après rotation) | Remise à 0 de l'offset + redémarrage indexer |

### 10. Chiffres clés à retenir

| Indicateur | Valeur |
|---|---|
| Adresse PLC | 192.168.95.2:502 |
| Adresse ScadaLTS | 192.168.90.107:8080 |
| Adresse Kali | 192.168.90.6 |
| Registre Feed2 (scénario 2) | Modifié à 45.8% |
| Requêtes flood (scénario 3) | 300 FC3 |
| Alertes Suricata scénario 3 | 487 (481 + 6) |
| Dashboard Wazuh scénario 3 | 7 236 événements |
| Combinaisons Hydra (scénario 4) | 25 (5 × 5) |
| FP Hydra scénario 4 | 80% (4/5) |
| Dashboard Wazuh scénario 4 | 12 024 événements |
| Timeout SOAR | 600 secondes (10 min) |
| Seuil règle 100101 | 8 req en 60 s |
| Seuil règle 100300 | 5 alertes en 30 s |

---

*Document de révision interne — EMSI 2025-2026*
