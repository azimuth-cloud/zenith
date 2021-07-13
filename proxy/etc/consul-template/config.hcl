consul {
    # The consul server will be populated using environment variables

    retry {
        # We limit the number of retries as we prefer to fail fast and let the
        # container scheduler do the work of retrying
        attempts = 3
    }
}

# Define the Nginx template
template {
    source = "/etc/nginx/nginx.conf"
    destination = "/var/run/nginx/nginx.conf"
    perms = 0644
}

# We use the exec capability of consul-template to run Nginx
exec {
    # Use the config file that we templated rather than from /etc/nginx
    command = "nginx -c /var/run/nginx/nginx.conf"
    # Use a splay to avoid all instances reloading at the same time when
    # we scale out
    splay = "10s"
    # Nginx should reload it's configuration on SIGHUP
    reload_signal = "SIGHUP"
}
