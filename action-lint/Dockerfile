FROM konstruktoid/alpine

LABEL "com.github.actions.name"="Lint - Upstream main"
LABEL "com.github.actions.description"="Upstream main ansible-lint"
LABEL "com.github.actions.icon"="shield"
LABEL "com.github.actions.color"="purple"

LABEL "repository"="https://github.com/konstruktoid/ansible-role-hardening"
LABEL "homepage"="https://github.com/konstruktoid/ansible-role-hardening"
LABEL "maintainer"="Thomas Sjögren <konstruktoid@users.noreply.github.com>"

ENV CRYPTOGRAPHY_DONT_BUILD_RUST 1
ENV PATH="${PATH}:/root/.local/bin"

RUN apk --update --no-cache add cargo gcc git g++ libffi-dev openssl-dev \
    musl-dev python3-dev py3-pip && \
    if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi && \
    python3 -m pip install --break-system-packages --no-cache-dir --upgrade jmespath passlib pipx && \
    python3 -m pipx install git+https://github.com/ansible/ansible-lint.git && \
    apk del gcc musl-dev python3-dev && \
    rm -rf /var/cache/*

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
