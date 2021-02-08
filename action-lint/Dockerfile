FROM konstruktoid/alpine:latest

LABEL "com.github.actions.name"="Konstruktoid YAML lint"
LABEL "com.github.actions.description"="YAML lint for multiple files"
LABEL "com.github.actions.icon"="mic"
LABEL "com.github.actions.color"="purple"

LABEL "repository"="https://github.com/konstruktoid/ansible-role-hardening"
LABEL "homepage"="https://github.com/konstruktoid/ansible-role-hardening"
LABEL "maintainer"="Thomas Sjögren <konstruktoid@users.noreply.github.com>"

RUN apk --update --no-cache add gcc musl-dev python3-dev py3-pip libffi-dev \
      libressl-dev cargo && \
    if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi && \
    pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir ansible ansible-lint yamllint && \
    rm -rf /var/cache/*

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
