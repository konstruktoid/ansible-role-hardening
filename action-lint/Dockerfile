FROM konstruktoid/alpine

LABEL "com.github.actions.name"="Lint - Upstream main"
LABEL "com.github.actions.description"="Upstream main ansible-lint"
LABEL "com.github.actions.icon"="shield"
LABEL "com.github.actions.color"="purple"

LABEL "repository"="https://github.com/konstruktoid/ansible-role-hardening"
LABEL "homepage"="https://github.com/konstruktoid/ansible-role-hardening"
LABEL "maintainer"="Thomas Sjögren <konstruktoid@users.noreply.github.com>"

ENV CRYPTOGRAPHY_DONT_BUILD_RUST 1

RUN apk --update --no-cache add cargo gcc git g++ libffi-dev openssl-dev \
    musl-dev python3-dev && \
    if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi && \
    python3 -m ensurepip --upgrade && \
    python3 -m pip install --no-cache-dir --upgrade pip && \
    python3 -m pip install --no-cache-dir wheel && \
    python3 -m pip install --no-cache-dir cryptography && \
    python3 -m pip install --no-cache-dir git+https://github.com/ansible/ansible-lint.git && \
    rm -rf /var/cache/*

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
