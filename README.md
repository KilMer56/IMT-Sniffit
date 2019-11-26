# Sniffit-py

L'objectif de ce projet était de fournir les outils nécessaires à l'étude du traffic internet de notre vie courant afin d'être utilisée lors de problématiques liées au Edge Computing

# Portée du projet

Afin de fournir une solution fonctionnelle en un temps assez court, la portée du projet a été limitée aux paquets TCP/IP. La solution fournit devaient également être le moins intrusive possible.

`TO COMPLETE`

# Solutions non retenues

## Mitmproxy

Mitmproxy permet la mise en place d'un proxy transparent. En installant un certificat particulie sur la machine cliente, il était alors possible d'analyser facilement et de manière détaillée tout le traffic passant sur ce proxy.

### Avantages :

- Analyse simple
- Analyse détaillée et bien segmentée (on sait précisément https quelle requête donne lieu à quel payload)

### Inconvénients :

- Intrusif
- Machine-dependent (requiert l'installation d'un certification sur chaque machine)
- Faible, voire complétement inutlisable, face au Certificate Pinning
  - Les applications natives s'assurent désormais qu'aucun certificat n'a été introduit afin d'éviter les attaques Man-In-The-Middle. Cette sécurité est contournable en décompilant le code de l'application, en extrayant le morceau de code responsable du pinning, puis en recompilant l'appliication
  - Application-dependent

## VPN sniffé avec Libtins

Libtins est un wrapper autour de libpcap permettant d'analyser le traffic entrant et sortant d'une machine. Écrit en C++, la librairie se décrit comme presque aussi performant que libpcap, avec des fonctionnalités en plus.

### Avantages :

- Performant
- Main sur de nombreux aspects du sniffing

### Désavantages :

- Langages que nous avons peu utilisé pour le moment
- Bas niveau nécessitant d'être prêt à mettre les mains dans le cambouis
- Document peu accessible, peu vulgarisée

# Solution retenue

## VPN sniffé avec PyShark

PyShark est une librairie se basant sur TShark. En lançant un processus TShark, la librairie récupère le contenu du traffic circulant sur la machine et l'encapsule dans des classes haut niveau.

### Avantages :

- Haut niveau facilitant l'utilisation de la librairie
- Python

### Désavantages :

- De base, récupère et écrit dans des fichiers pcap énormément de données
- Documentation seulement partielle
  - _To easily view the different attributes of the layer, you can simply run dir(packet.my_layer)_, source : http://kiminewt.github.io/pyshark/

# Architecture de la solution

`TODO insert image`

## Recorder

Responsable de la capture du traffic, ce script minimaliste stocke les données dans un fichier pcap utilisable à posteriori

Le traffic est volontairement stocké dans un fichier plutôt qu'être analysé à la volée afin d'éviter la surcharge de notre VPS disposant de peu de ressources déjà bien mises à mal avec le VPN.

## Analyzer

Responsable de l'analyse du traffic. L'analyzer vient parcourir les packets enregistrés et viens stocker les informations intéressantes (taille du payload, timestamp) dans le stream correspondant.

Si le temps entre deux packets dépassent l'écart maximum pour ce stream, alors son contenu est flush vers la base de données. Le même processus se produit également si le stream n'est pas fermé à la fin de l'exécution du script.

## ElasticSearch et Kibana

L'utilisation de ElasticSearch permet une bonne scalabilité à moindre coût. En fournissant des agrégations rapides, il permet une analyse performante des données. De plus, Kibana fournit énormément de représentation toutes faites tels que les représentations Timelion ou TSVB pour les données time series.

Ces deux composants peuvent être déployés rapidement grâce à docker et docker-compose

`TODO UNE IMAGE`

# Exemples de données obtenus

`TODO UNE IMAGE`
