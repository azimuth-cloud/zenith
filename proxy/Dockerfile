ARG NGINX_VERSION=1.21.6
ARG GOMPLATE_VERSION=v3.10.0


# Use a named build stage for gomplate
FROM hairyhenderson/gomplate:${GOMPLATE_VERSION} AS gomplate


FROM nginx:${NGINX_VERSION}

# Install tini, which we will use to marshal the Nginx processes
RUN apt-get update && \
    apt-get install -y tini && \
    rm -rf /var/lib/apt/lists/*

# Remove unused file and make config directories for the Nginx user
RUN rm -rf /etc/nginx/conf.d /docker-entrypoint.sh /docker-entrypoint.d && \
    mkdir -p /var/cache/nginx /var/run/nginx && \
    chown nginx:nginx /var/cache/nginx /var/run/nginx

# Install gomplate from the previous stage
COPY --from=gomplate /gomplate /usr/bin/gomplate

COPY ./bin /usr/bin/
COPY ./etc /etc/

# The Nginx user has UID 101
USER 101
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["/usr/bin/nginx-start"]
