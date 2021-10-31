# FROM overridden in pipeline, typically debian/python
FROM debian/none

USER root

RUN curl -L https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.16.0/kubeseal-linux-amd64 -o - | \
    tar -xz -C /usr/local/bin -f - && \
    chmod +x /usr/local/bin/kubeseal

RUN curl -L https://mirror.openshift.com/pub/openshift-v4/clients/oc/4.6/linux/oc.tar.gz -o - | \
    tar -xz -C /usr/local/bin -f - && \
    chmod +x /usr/local/bin/oc

USER 1001:1001

ENV PYTHON_VERSION=3.8 \
    PIP_VERSION=3.8 \
    PATH=$PATH:/$HOME/.local/bin/
    PIP_NO_CACHE_DIR=off \

COPY --chown=1001:1001 src/python $HOME/python

RUN chown -R 1001:1001 $HOME/*

CMD ["/bin/env","python3","app/run.py"]