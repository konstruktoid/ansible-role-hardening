FROM konstruktoid/alpine:latest

LABEL "com.github.actions.name"="Konstruktoid YAML lint"
LABEL "com.github.actions.description"="YAML lint for multiple files"
LABEL "com.github.actions.icon"="mic"
LABEL "com.github.actions.color"="purple"

LABEL "repository"="https://github.com/konstruktoid/ansible-role-hardening"
LABEL "homepage"="https://github.com/konstruktoid/ansible-role-hardening"
LABEL "maintainer"="Thomas Sjögren <konstruktoid@users.noreply.github.com>"

RUN \
    apk --update --no-cache add gcc libffi-dev linux-headers make musl-dev \
        openssl-dev py2-pip python2-dev && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ansible-lint yamllint && \
    apk del gcc libffi-dev linux-headers make musl-dev openssl-dev && \
    rm -rf /var/cache/*

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
