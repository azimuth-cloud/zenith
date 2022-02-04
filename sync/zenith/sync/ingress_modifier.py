INGRESS_MODIFIERS_ENTRY_POINT_GROUP = "zenith.sync.ingress_modifiers"


class IngressModifier:
    """
    Base class for an ingress modifier.
    """
    def configure_defaults(self, ingress):
        """
        Applies any default configuration to the given ingress. The ingress should
        be modified in-place.
        """

    def configure_backend_protocol(self, ingress, protocol):
        """
        Applies any configuration required to enable the specified backend protocol
        for the specified ingress. The ingress should be modified in-place.
        """
        raise NotImplementedError

    def configure_read_timeout(self, ingress, timeout):
        """
        Applies any configuration required to set the specified read timeout for the
        specified ingress. The ingress should be modified in-place.
        """
        raise NotImplementedError

    def configure_tls_client_certificates(self, ingress, namespace, secret_name):
        """
        Applies any configuration required to enable the handling of TLS client certificates
        for the specified ingress. The ingress should be modified in-place.
        """
        raise NotImplementedError

    def configure_authentication(
        self,
        ingress,
        # The URL of the authentication service
        auth_url,
        # The signin URL that should be redirected to on an authentication failure
        # Can be None if there is no signin URL and the 401/403 response should be returned
        signin_url,
        # The parameter that the original URL should go in when redirecting to the signin URL
        next_url_param,
        # Dictionary of headers to pass to the authentication service
        auth_headers,
        # List of headers to copy from the authentication response to the upstream request
        upstream_headers
    ):
        """
        Applies any configuration required to enable the specified authentication for the
        specified ingress. The ingress should be modified in-place.
        """
        raise NotImplementedError


class NginxIngressModifier(IngressModifier):
    """
    Ingress modifier for the Nginx Ingress Controller.
    """
    # By default, don't buffer responses and allow any size of client body
    DEFAULT_ANNOTATIONS = {
        "nginx.ingress.kubernetes.io/proxy-buffering": "off",
        "nginx.ingress.kubernetes.io/proxy-body-size": "0",
    }
    BACKEND_PROTOCOL_ANNOTATION = "nginx.ingress.kubernetes.io/backend-protocol"
    READ_TIMEOUT_ANNOTATION = "nginx.ingress.kubernetes.io/proxy-read-timeout"
    # Annotations for TLS client certificate authentication
    AUTH_TLS_SECRET_ANNOTATION = "nginx.ingress.kubernetes.io/auth-tls-secret"
    AUTH_TLS_VERIFY_CLIENT_ANNOTATION = "nginx.ingress.kubernetes.io/auth-tls-verify-client"
    AUTH_TLS_PASS_CERT_ANNOTATION = "nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream"
    # Annotations for external authentication service
    AUTH_URL_ANNOTATION = "nginx.ingress.kubernetes.io/auth-url"
    AUTH_SIGNIN_ANNOTATION = "nginx.ingress.kubernetes.io/auth-signin"
    AUTH_SIGNIN_REDIRECT_PARAM_ANNOTATION = "nginx.ingress.kubernetes.io/auth-signin-redirect-param"
    AUTH_RESPONSE_HEADERS_ANNOTATION = "nginx.ingress.kubernetes.io/auth-response-headers"
    AUTH_SNIPPET_ANNOTATION = "nginx.ingress.kubernetes.io/auth-snippet"

    def configure_defaults(self, ingress):
        ingress["metadata"]["annotations"].update(self.DEFAULT_ANNOTATIONS)

    def configure_backend_protocol(self, ingress, protocol):
        ingress["metadata"]["annotations"][self.BACKEND_PROTOCOL_ANNOTATION] = protocol.upper()

    def configure_read_timeout(self, ingress, timeout):
        ingress["metadata"]["annotations"][self.READ_TIMEOUT_ANNOTATION] = str(timeout)

    def configure_tls_client_certificates(self, ingress, namespace, secret_name):
        ingress["metadata"]["annotations"].update({
            self.AUTH_TLS_SECRET_ANNOTATION: f"{namespace}/{secret_name}",
            self.AUTH_TLS_VERIFY_CLIENT_ANNOTATION: "optional",
            self.AUTH_TLS_PASS_CERT_ANNOTATION: "true",
        })

    def configure_authentication(
        self,
        ingress,
        auth_url,
        signin_url,
        next_url_param,
        auth_headers,
        upstream_headers
    ):
        annotations = ingress["metadata"]["annotations"]
        annotations[self.AUTH_URL_ANNOTATION] = auth_url
        if signin_url:
            annotations.update({
                self.AUTH_SIGNIN_ANNOTATION: signin_url,
                self.AUTH_SIGNIN_REDIRECT_PARAM_ANNOTATION: next_url_param,
            })
        if auth_headers:
            # Use a custom snippet to set the auth headers
            annotations[self.AUTH_SNIPPET_ANNOTATION] = "\n".join([
                f"proxy_set_header {name} {value};"
                for name, value in auth_headers.items()
            ])
        if upstream_headers:
            annotations[self.AUTH_RESPONSE_HEADERS_ANNOTATION] = ",".join(upstream_headers)
