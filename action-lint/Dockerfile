FROM konstruktoid/alpine:latest

LABEL "com.github.actions.name"="Konstruktoid YAML lint"
LABEL "com.github.actions.description"="YAML lint for multiple files"
LABEL "com.github.actions.icon"="mic"
LABEL "com.github.actions.color"="purple"

LABEL "repository"="https://github.com/konstruktoid/ansible-role-hardening"
LABEL "homepage"="https://github.com/konstruktoid/ansible-role-hardening"
LABEL "maintainer"="Thomas Sjögren <konstruktoid@users.noreply.github.com>"

ENV CRYPTOGRAPHY_DONT_BUILD_RUST 1

RUN apk --update --no-cache add cargo gcc g++ libffi-dev openssl-dev \
    musl-dev py3-pip python3-dev && \
    if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi && \
    pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir wheel && \
    pip3 install --no-cache-dir cryptography && \
    pip3 install --no-cache-dir ansible ansible-lint yamllint && \
    rm -rf /var/cache/*

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
