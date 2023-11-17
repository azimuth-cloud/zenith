ARG GOMPLATE_VERSION


# Use a named build stage for gomplate
FROM hairyhenderson/gomplate:${GOMPLATE_VERSION} AS gomplate


# This intermediate image is used to fetch the GPG key for the NGINX repo
# without polluting the runtime image with GPG packages
FROM ubuntu:jammy AS nginx-gpg-key

ENV NGINX_GPG_KEY="573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"

RUN apt-get update && \
    apt-get install -y gnupg2 && \
    rm -rf /var/lib/apt/lists/*

RUN gpg2 --keyserver hkp://keyserver.ubuntu.com:80 --keyserver-options timeout=10 --recv-keys "$NGINX_GPG_KEY" && \
    gpg2 --export "$NGINX_GPG_KEY" > /usr/share/keyrings/nginx-archive-keyring.gpg


FROM ubuntu:jammy

ARG NGINX_VERSION

# Copy the GPG key from the intermediate container
COPY --from=nginx-gpg-key /usr/share/keyrings/nginx-archive-keyring.gpg /usr/share/keyrings/

# We install NGINX from the official repository
RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y ca-certificates && \
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/mainline/ubuntu/ jammy nginx" \
      > /etc/apt/sources.list.d/nginx.list && \
    apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
      "nginx=${NGINX_VERSION}*" \
      "nginx-module-njs=${NGINX_VERSION}*" \
      tini \
    && \
    rm -rf /var/lib/apt/lists/* && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log && \
    rm -rf /etc/nginx/conf.d && \
    mkdir -p /var/cache/nginx /var/run/nginx && \
    chown nginx:nginx /var/cache/nginx /var/run/nginx

# Install gomplate from the previous stage
COPY --from=gomplate /gomplate /usr/bin/gomplate

COPY ./bin /usr/bin/
COPY ./etc /etc/

ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["/usr/bin/nginx-start"]
