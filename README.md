# Nexus Auditor

Nexus Auditor est une application d'audit de code assisté par IA. Elle associe
une interface React, une API FastAPI et un serveur Ollama pour analyser un
dépôt, suivre la progression d'un scan et consulter les résultats.

## Fonctions

- Préparation et lancement d'un scan avec profils et modes configurables.
- Suivi des étapes, journaux, résultats et historique des audits.
- Export des résultats et du rapport, et génération de propositions de correctifs.
- Connexion à un serveur Ollama local ou distant.

Les résultats sont des indications à vérifier : une analyse automatisée peut
produire des faux positifs ou manquer des problèmes. N'analysez que les dépôts
pour lesquels vous disposez des autorisations nécessaires.

## Prérequis

- Docker et Docker Compose pour l'installation conteneurisée ; ou Python 3.11,
  Git et Node.js (version compatible avec Vite 7 : 20.19 ou ultérieure dans
  la branche 20, ou 22.12 ou ultérieure) pour le
  développement local.
- Un serveur [Ollama](https://ollama.com/) accessible et un modèle installé.
  Les modèles et services externes sont soumis à leurs propres conditions.

## Démarrage avec Docker Compose

Depuis la racine du dépôt :

```bash
mkdir -p audit_logs
docker compose up --build
```

L'interface est accessible sur <http://localhost:3000> et l'API sur
<http://localhost:8000> ; sa documentation interactive se trouve sur
<http://localhost:8000/docs>. La configuration Compose pointe par défaut vers
Ollama sur `host.docker.internal:11434`. Vérifiez que le serveur est accessible
depuis le conteneur et sélectionnez un modèle disponible dans l'interface.

Pour arrêter les services :

```bash
docker compose down
```

## Développement local

Dans un premier terminal, depuis la racine du dépôt :

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt
cd backend
uvicorn backend:app --reload --host 127.0.0.1 --port 8000
```

Dans un second terminal :

```bash
cd frontend
npm ci
npm run dev
```

Ouvrez l'adresse indiquée par Vite. Le serveur de développement transmet les
requêtes `/api` à l'API locale sur le port 8000. Par défaut, le backend utilise
`http://localhost:11434/api/generate` pour Ollama ; `OLLAMA_URL` permet de
changer cette adresse au démarrage du backend. L'interface permet également de
configurer une connexion distante.

## Données et tests

Les journaux et l'historique sont des données d'exécution : vérifiez leur
contenu avant de les partager. Le répertoire `audit_logs/` et les fichiers
`audit_history*.json` sont ignorés pour les nouveaux fichiers par Git ; les
fichiers déjà suivis continuent toutefois d'être suivis. Un exemple de réponse
fictive se trouve dans `fixtures/audit_responses/`.

Pour lancer les tests Python après installation de `pytest` dans l'environnement
virtuel :

```bash
python -m pip install pytest
python -m pytest -q backend/tests
```

Pour vérifier la construction de l'interface :

```bash
cd frontend
npm run build
```

## License

Les contributions de Nexus Auditor pour lesquelles les droits nécessaires sont
détenus sont distribuées sous [Apache License 2.0](LICENSE). Les composants et
ressources tiers conservent leurs propres licences ; voir
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

La licence Apache ne concède pas de droit d'utilisation des noms commerciaux,
marques ou identités commerciales Luneyro, sous réserve des usages limités
expressément prévus par sa section 6.
