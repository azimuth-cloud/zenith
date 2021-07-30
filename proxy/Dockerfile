#####
## Container image spec for tunnel-server dynamic proxy server
#####

# Use a named build stage for consul-template
ARG CONSUL_TEMPLATE_VERSION=0.26.0
FROM hashicorp/consul-template:${CONSUL_TEMPLATE_VERSION} AS consul-template


FROM nginx

# Remove unused file and make config directories for the Nginx user
RUN rm -rf /etc/nginx/conf.d /docker-entrypoint.d/* && \
    mkdir -p /var/cache/nginx /var/run/nginx && \
    chown nginx:nginx /var/cache/nginx /var/run/nginx

# Install consul-template from previous stage
COPY --from=consul-template /bin/consul-template /usr/bin/

# Copy in configuration files
COPY ./bin /usr/bin/
COPY ./etc /etc/

# The Nginx user has UID 101
USER 101

# We run Nginx via consul-template
CMD ["/usr/bin/consul-template-start"]
