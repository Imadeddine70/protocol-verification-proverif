# Vérification d'un protocole d'échange de clé avec ProVerif

Projet du module « Méthodes formelles pour la sécurité » (ESTIN, 2e année du cycle ingénieur, spécialité cybersécurité, 2023-2024), repris et complété.

Un client A et un serveur B veulent partager un secret `s` :

```
A -> B : pk(skA)
B -> A : aenc( sign( (pk(skB), k), skB ), pk(skA) )     k = clé de session fraîche
A -> B : senc(s, k)
```

## Le défaut

La signature de B ne dit pas **pour qui** la clé `k` a été générée. Un intrus `I` demande une clé à B pour lui-même, récupère `aenc(sign((pk(skB),k),skB), pk(skI))`, la déchiffre, puis la rechiffre avec `pk(skA)` et la rejoue à A. A croit parler à B et chiffre `s` avec une clé que `I` connaît.

## La correction

B signe aussi l'identité du client visé, et A vérifie que c'est la sienne :

```
B -> A : aenc( sign( (pk(skA), pk(skB), k), skB ), pk(skA) )
```

## Les modèles

| Fichier | Contenu |
|---|---|
| `models/flawed_protocol.pv` | version vulnérable ; ProVerif doit trouver que `attacker(s)` est accessible et que la correspondance d'authentification est fausse |
| `models/fixed_protocol.pv` | version corrigée (serveur **et** client) ; secret et authentification doivent être prouvés, avec une requête de non-vacuité |

```bash
proverif models/flawed_protocol.pv
proverif models/fixed_protocol.pv
```

## Une erreur dans la première version de ce travail

Dans le rapport d'origine, la correction n'avait modifié que la ligne d'envoi du serveur (le message signé devenait `(pk(skA), pk(skB), k)`). Le client continuait d'attendre un message signé de la forme `(pk(skB), k)`. Les deux formes ne se correspondent pas : le client rejetait donc tous les messages et n'envoyait jamais `s`. ProVerif répondait « `not attacker(s)` est vrai », mais pour une mauvaise raison : le modèle était bloqué, la propriété n'était pas démontrée.

Le modèle corrigé de ce dépôt change les deux côtés, et ajoute la requête 3 (« le client peut-il atteindre la fin du protocole ? ») pour détecter ce genre de blocage.

## Résultats

**Version vulnérable** (`results/flawed_output.txt`) : les deux requêtes sont fausses.

- `not attacker(s[])` est **faux** : l'intrus obtient le secret `s`.
- `ClientAccept(p,k) ==> ServerSend(p,k)` est **faux** : A accepte une clé que B a générée pour une autre clé publique, celle de l'intrus. C'est le rejeu décrit plus haut.

**Version corrigée** (`results/fixed_output.txt`) :

- `not attacker(s[])` est **vrai** : le secret reste confidentiel.
- `ClientAccept(p,k) ==> ServerSend(p,k)` est **vrai** : toute clé acceptée par A a bien été générée par B pour la clé publique de A.
- `not event(ClientAccept(p,k))` est **faux**, ce qui est voulu : l'événement est atteignable, donc la propriété d'authentification n'est pas vide (non-vacuité).

## Limites

- Modèle de Dolev-Yao symbolique : la cryptographie est supposée parfaite, aucune attaque sur les primitives elles-mêmes.
- Une seule propriété de secret et une correspondance non injective (pas de protection contre le rejeu).
- Le protocole est un exemple d'école, pas un protocole déployé.

## Licence

MIT
