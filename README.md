# The Social-Engineer Toolkit (SET)

*[Read this in English](https://github.com/trustedsec/social-engineer-toolkit)*

Le Social-Engineer Toolkit est un framework de tests d'intrusion open source destiné aux évaluations d'ingénierie sociale autorisées. SET propose des vecteurs d'attaque guidés pour les équipes de sécurité qui doivent tester la vigilance des utilisateurs, valider des contrôles de sécurité et mener des exercices red-team réalisés avec le consentement des parties concernées.

SET est un projet TrustedSec écrit par David Kennedy (ReL1K) / @HackingDave.

## Utilisation responsable

SET est destiné uniquement à des tests autorisés, pour lesquels une permission explicite et un périmètre ont été définis. N'utilisez pas SET contre des systèmes, comptes, réseaux ou personnes sans leur consentement. Consultez la licence dans [readme/LICENSE](readme/LICENSE) avant d'utiliser ou de distribuer SET.

## Plateformes prises en charge

- Linux
- macOS, expérimental
- Windows via WSL/WSL2 Kali ou un autre environnement Linux pris en charge

SET 8.1.3 cible Python 3.11 à 3.13.

## Installation

### Kali Linux / WSL

```bash
sudo apt update
sudo apt install set -y
```

### Depuis les sources

```bash
git clone https://github.com/trustedsec/social-engineer-toolkit/ setoolkit/
cd setoolkit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Pour l'ancienne disposition système, lancez l'installateur avec des privilèges élevés :

```bash
sudo python3 setup.py
```

L'installateur historique copie SET vers `/usr/local/share/setoolkit`, écrit `/etc/setoolkit/set.config`, et crée `/usr/local/bin/setoolkit`.

## Utilisation

Lancez la console interactive :

```bash
sudo setoolkit
```

Depuis une copie des sources, vous pouvez aussi lancer :

```bash
sudo ./setoolkit
```

Le manuel utilisateur complet est disponible sur [readme/User_Manual.pdf](https://github.com/trustedsec/social-engineer-toolkit/raw/master/readme/User_Manual.pdf).

## Langue

Ce fork est bilingue. Par défaut, SET s'affiche en anglais, exactement comme en amont. Pour basculer l'interface en français, définissez `SET_LANG=fr` avant de lancer l'outil :

```bash
export SET_LANG=fr
sudo -E setoolkit
```

(le `-E` conserve la variable d'environnement sous `sudo`). Toute valeur autre que `fr` retombe sur l'anglais. Les chaînes françaises vivent dans [src/core/i18n_fr.py](src/core/i18n_fr.py) ; le mécanisme de traduction est dans [src/core/i18n.py](src/core/i18n.py).

## Développement

```bash
python -m pip install -e .
python -m pip install pytest
python -m compileall -q .
pytest -q
```

## Signalement de failles de sécurité

Merci de signaler les vulnérabilités en suivant le processus décrit dans [SECURITY.md](SECURITY.md). N'ouvrez pas d'issue publique pour une vulnérabilité exploitable.

## Bugs et suggestions

Pour les rapports de bugs non sensibles ou les demandes d'amélioration, ouvrez une issue sur https://github.com/trustedsec/social-engineer-toolkit/issues en précisant la version de SET, la plateforme, la version de Python et les étapes de reproduction.

---

*Cette traduction française est maintenue dans un fork communautaire ([abiyeenzo/social-engineer-toolkit](https://github.com/abiyeenzo/social-engineer-toolkit)) et n'est pas affiliée à TrustedSec.*
