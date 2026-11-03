# Image d'outils IT320 : OSINT + détection + clients MISP
FROM python:3.12-slim

# Réseau d'école lent ou saturé : le délai de lecture par défaut de pip (15 s) a fait échouer le build le 28 octobre 2026
ENV PIP_DEFAULT_TIMEOUT=120 PIP_RETRIES=10

# build-essential : dnstwist[full] dépend de py-tlsh, sans wheel précompilée pour Python 3.12 (compilation C++ au pip install)
RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl ca-certificates yara jq dnsutils whois build-essential \
    && rm -rf /var/lib/apt/lists/*

# pysigma-backend-kusto : conversion `sigma convert -t kusto -p sysmon` (Microsoft Sentinel / Defender) en plus de splunk et lucene/elasticsearch
RUN pip install --no-cache-dir \
      dnstwist[full] yara-python pymisp requests \
      sigma-cli pysigma-backend-splunk pysigma-backend-elasticsearch pysigma-backend-kusto pysigma-pipeline-sysmon pysigma-pipeline-windows \
      msticpy jupyterlab pandas

# theHarvester : le paquet PyPI du même nom n'est pas l'outil (version 0.0.1 sans commande) ; installation depuis le
# dépôt officiel, version épinglée en octobre 2026, dans un environnement à part (dépendances incompatibles avec msticpy).
ARG THEHARVESTER_VERSION=4.11.1
RUN python3 -m venv /opt/theharvester \
    && /opt/theharvester/bin/pip install --no-cache-dir git+https://github.com/laramies/theHarvester@${THEHARVESTER_VERSION} \
    && ln -s /opt/theharvester/bin/theHarvester /usr/local/bin/theHarvester

# Outils Go précompilés (subfinder, dnsx, nuclei, httpx) via les releases GitHub, installés APRÈS pip : la bibliothèque
# Python httpx (dépendance de pymisp/msticpy) installe une commande /usr/local/bin/httpx qui écraserait celle de ProjectDiscovery.
# Assets attendus : <outil>_<version>_linux_amd64.zip — vérifier l'URL avant le build si l'asset a changé de nom
# (https://github.com/projectdiscovery/<outil>/releases). Versions épinglées en octobre 2026.
ARG SUBFINDER_VERSION=2.16.0
ARG DNSX_VERSION=1.3.1
ARG NUCLEI_VERSION=3.11.1
ARG HTTPX_VERSION=1.12.0
RUN curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip -o /tmp/sf.zip \
    && curl -sL https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_amd64.zip -o /tmp/dx.zip \
    && python3 -c "import zipfile;[zipfile.ZipFile(z).extractall('/usr/local/bin') for z in ['/tmp/sf.zip','/tmp/dx.zip']]" \
    && curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip -o /tmp/nu.zip \
    && curl -sL https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip -o /tmp/hx.zip \
    && python3 -c "import zipfile;[zipfile.ZipFile(z).extractall('/usr/local/bin') for z in ['/tmp/nu.zip','/tmp/hx.zip']]" \
    && chmod +x /usr/local/bin/subfinder /usr/local/bin/dnsx /usr/local/bin/nuclei /usr/local/bin/httpx && rm /tmp/*.zip
# nuclei : outil ACTIF, réservé au domaine bac à sable (charte IT320). Les templates se téléchargent avec `nuclei -update-templates`.

# /work = racine du dépôt plateforme (montée par docker-compose.yml) : /work/tools, /work/rules, /work/data, /work/out
WORKDIR /work
COPY *.py /usr/local/bin/
RUN chmod +x /usr/local/bin/*.py
CMD ["bash"]
