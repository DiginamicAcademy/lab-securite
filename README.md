# Lab de test — DIGICHEESE

> Environnement Docker à monter pour **tester les concepts du cours en local**.
> Deux versions de la même API coexistent : une **vulnérable** (à comprendre, à casser) et une **sécurisée** (à comparer, à corriger).
> Sujet d'étude : fromagerie en TPE, refonte d'une app de gestion interne.

> [!DANGER]
> Le service `vulnerable` contient des failles volontaires (injection SQL, XSS, mots de passe faibles, pas de contrôle d'accès, fuite de config).
> **Usage strictement limité à ce lab local.** Ne jamais l'exposer sur un réseau public ni en production.

## Cours qui montent ce lab

| Cours | Journées | Ce qu'on y fait |
| --- | --- | --- |
| [Les vulnérabilités et techniques d'attaques](https://github.com/DiginamicAcademy/cours-securite-vulnerabilites-attaques) | J2-J3 | Casser `vulnerable`, endpoint par endpoint, puis chaîner les failles |
| [Authentification](https://github.com/DiginamicAcademy/cours-securite-authentification) | J4 | Comparer le stockage des mots de passe (MD5 contre bcrypt), jeton et session |
| [Applications et protocoles](https://github.com/DiginamicAcademy/cours-securite-applications-protocoles) | J7-J9 | Corriger, sécuriser le code et les API, brancher les tests dans la CI |

Les cours [Fondamentaux de la cybersécurité](https://github.com/DiginamicAcademy/cours-securite-fondamentaux) et [Cryptographie](https://github.com/DiginamicAcademy/cours-securite-cryptographie) mettent en scène la même fromagerie dans leurs exercices sans monter les conteneurs. Le détail, journée par journée, en fin de document.

---

## 1. Prérequis

- Docker + Docker Compose (v2).
- `curl` ou un client HTTP (Postman, httpie) pour les requêtes.
- 4 Go de RAM disponibles.

## 2. Démarrage

```bash
git clone https://github.com/DiginamicAcademy/lab-digicheese.git
cd lab-digicheese
docker compose up --build -d
docker compose ps
```

| Service | URL | Rôle |
| --- | --- | --- |
| `vulnerable` | http://localhost:8080 | API volontairement faille — modules J2-J3 |
| `secure` | http://localhost:8081 | API corrigée — modules J4 et J7-J9 |
| `db` | localhost:3306 | MySQL 8.4, base `fromagerie` |
| `cve` | http://localhost:8082 | Mini-app obsolète (dépendance signalée) — TD « exploiter / corriger » (J3) |

Arrêt :

```bash
docker compose down          # stoppe les conteneurs
docker compose down -v       # + supprime les données (repart à zéro)
```

### TD « exploiter / corriger une CVE » (J3)

Le service `cve` est une mini-app Flask **volontairement obsolète** : elle utilise
**Jinja2 3.1.2**, affecté par **CVE-2024-22195** (GHSA-h5c8-rqwp-cp95 — le filtre `xmlattr` accepte des clés d'attribut contenant des espaces, ce qui permet d'injecter du HTML).
Elle met le filtre en scène pour que le mécanisme soit observable :

| Étape | Ce que fait l'apprenant |
| --- | --- |
| 1. Exploiter | constater l'injection dans la page de recherche `http://localhost:8082/` |
| 2. Documenter | expliquer le mécanisme (filtre `xmlattr`, échappement des attributs) |
| 3. Corriger | monter Jinja2 (>= 3.1.3) **et** valider les clés côté applicatif, reconstruire, vérifier que l'exploit casse |

Le TD correspondant est le chapitre 09 du cours
[Les vulnérabilités et techniques d'attaques](https://github.com/DiginamicAcademy/cours-securite-vulnerabilites-attaques/blob/main/09-cve-et-course.md),
qui reprend l'exploitation, la documentation du mécanisme et le correctif.

> Ce service n'a **pas** de base de données ni de réseau sortant : la faille et sa
> correction sont contenues dans le code de l'app et sa version de dépendance.

## 3. Ce qu'on peut tester

### Depuis `vulnerable` (J2-J3 : comprendre les failles)

| Faille OWASP | Endpoint | Ce qu'il se passe |
| --- | --- | --- |
| **A03 — Injection SQL** | `GET /products/search?q=` | La saisie est concaténée dans la requête |
| **A07 — Auth défaillante** | `POST /login` | Mots de passe MD5 sans sel, voire en clair |
| **A03 — XSS réfléchi** | `GET /comments?q=` | La saisie est réinjectée sans échappement |
| **A01 — Broken Access Control** | `GET /admin/users` | Aucun contrôle de rôle |
| **A05 — Info leak** | `GET /debug/config` | Config et variables d'environnement exposées |

Exemples :

```bash
# Injection SQL — lister tous les produits au lieu de filtrer
curl "http://localhost:8080/products/search?q=' OR '1'='1"

# XSS — injecter un script dans le paramètre de recherche
curl "http://localhost:8080/comments?q=<script>alert(1)</script>"

# Fuite de config
curl http://localhost:8080/debug/config
```

### Depuis `secure` (J7-J9 : voir les corrections)

Même API, mêmes endpoints, mais requête paramétrée, échappement HTML, bcrypt, token signé, contrôle de rôle, pas de fuite de config.

```bash
# La même injection est neutralisée
curl "http://localhost:8081/products/search?q=' OR '1'='1"

# Login → renvoie un token signé
curl -X POST -F "username=admin" -F "password=admin123" http://localhost:8081/login

# Admin : token requis, contrôle de rôle
curl -H "Authorization: Bearer <TOKEN>" http://localhost:8081/admin/users
```

## 4. Outils de test recommandés

| Usage | Outils |
| --- | --- |
| Requêtes HTTP | `curl`, httpie, Postman, Insomnia |
| Injection SQL (lab only) | `sqlmap` en local contre `localhost:8080` |
| Analyse de code | `bandit` (Python), `semgrep`, `trivy` |
| Dépendances | `pip-audit`, `safety` |
| En-têtes HTTP | `curl -I`, observatory.mozilla.org |

## 5. Comptes de démonstration

| Login | Mot de passe | Rôle | Note |
| --- | --- | --- | --- |
| `alice` | `alice123` | user | En clair en base (faille A07 côté vulnérable) |
| `bruno` | `bruno123` | user | En clair en base |
| `admin` | `admin123` | admin | En clair en base |
| `charlie` | `password` | user | Hash MD5 sans sel |
| `zoe` | `zoe123` | user | Hash bcrypt — fonctionne sur `secure` |
| `marc` | `adminSecure1!` | admin | Hash bcrypt — fonctionne sur `secure` |

> Sur `secure`, les comptes `alice` / `bruno` / `admin` / `charlie` **refusent la connexion** (hash non bcrypt) : c'est volontaire, pour montrer que le stockage de mots de passe a changé. Seuls `zoe` et `marc` (bcrypt) s'y connectent. Voir `secure/app.py` (dans ce dossier) et l'exercice de migration.

## 6. Correspondance cours ↔ lab

| Journée | Service | Usage |
| --- | --- | --- |
| J2 — Vulnérabilités | `vulnerable` | Reconnaître chaque faille sur un endpoint réel |
| J3 — Techniques d'attaque | `vulnerable` | Chaîner les failles, comprendre le mode opératoire |
| J4 — Authentification | `db` + `secure` | Stockage des mots de passe (MD5 vs bcrypt), jeton et session |
| J7 — Sécurité du code | `secure` vs `vulnerable` | Comparer côte à côte, corriger |
| J8 — API et données | `secure` | Auth, rate limit, minimisation des données |
| J9 — Réseaux et cycle de vie | les deux | Tests automatisés, en-têtes, CI sécurisée |
