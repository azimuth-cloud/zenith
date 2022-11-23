import re

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
        next_url_param = None,
        # Dictionary of headers to pass to the authentication service
        request_headers = None,
        # List of headers to copy from the authentication response to the upstream request
        # Each entry can be either a single string, the name of the response header to copy,
        # or an (auth response header, upstream header) pair to rename the header
        response_headers = None,
        # List of cookies to copy from the authentication response to the main response
        response_cookies = None
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
        "nginx.ingress.kubernetes.io/proxy-buffer-size": "16k",
    }
    BACKEND_PROTOCOL_ANNOTATION = "nginx.ingress.kubernetes.io/backend-protocol"
    READ_TIMEOUT_ANNOTATION = "nginx.ingress.kubernetes.io/proxy-read-timeout"
    # Annotations for TLS client certificate authentication
    AUTH_TLS_SECRET_ANNOTATION = "nginx.ingress.kubernetes.io/auth-tls-secret"
    AUTH_TLS_VERIFY_CLIENT_ANNOTATION = "nginx.ingress.kubernetes.io/auth-tls-verify-client"
    AUTH_TLS_PASS_CERT_ANNOTATION = "nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream"
    # Annotations for auth subrequests
    AUTH_URL_ANNOTATION = "nginx.ingress.kubernetes.io/auth-url"
    AUTH_SIGNIN_ANNOTATION = "nginx.ingress.kubernetes.io/auth-signin"
    AUTH_SIGNIN_REDIRECT_PARAM_ANNOTATION = "nginx.ingress.kubernetes.io/auth-signin-redirect-param"
    AUTH_SNIPPET_ANNOTATION = "nginx.ingress.kubernetes.io/auth-snippet"
    # Annotation for applying additional configuration
    CONFIGURATION_SNIPPET_ANNOTATION = "nginx.ingress.kubernetes.io/configuration-snippet"

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
        next_url_param = None,
        request_headers = None,
        response_headers = None,
        response_cookies = None
    ):
        annotations = ingress["metadata"]["annotations"]
        annotations[self.AUTH_URL_ANNOTATION] = auth_url
        if signin_url:
            annotations[self.AUTH_SIGNIN_ANNOTATION] = signin_url
            if next_url_param:
                annotations[self.AUTH_SIGNIN_REDIRECT_PARAM_ANNOTATION] = next_url_param
        if request_headers:
            # Use a custom snippet to set the request headers for the auth request
            annotations[self.AUTH_SNIPPET_ANNOTATION] = "\n".join([
                f"proxy_set_header {name} {value};"
                for name, value in request_headers.items()
            ])
        config_snippet = []
        if response_headers:
            for idx, headers in enumerate(response_headers):
                if isinstance(headers, (list, tuple)):
                    auth_header, upstream_header = headers
                else:
                    auth_header = upstream_header = headers
                # Convert the auth header to an Nginx variable name
                auth_header = auth_header.lower().replace("-", "_")
                config_snippet.extend([
                    f"auth_request_set $auth_header_{idx} $upstream_http_{auth_header};",
                    f"proxy_set_header {upstream_header} \"$auth_header_{idx}\";",
                ])
        if response_cookies:
            config_snippet.extend(
                [
                    f"auth_request_set $auth_cookie_{name} $upstream_cookie_{name};"
                    for name in response_cookies
                ] +
                [
                    "access_by_lua_block {",
                    "  local auth_set_cookie = ngx.var.auth_cookie",
                ] + [
                    "\n".join([
                        f"  if ngx.var.auth_cookie_{name} ~= \"\" then",
                        f"    auth_set_cookie = \"{name}=\" .. ngx.var.auth_cookie_{name} .. \"; \" .. auth_set_cookie",
                        "  end",
                    ])
                    for name in response_cookies
                ] + [
                    "  if auth_set_cookie ~= \"\" then",
                    "    ngx.header[\"Set-Cookie\"] = auth_set_cookie",
                    "  end",
                    "}",
                ]
            )
        if config_snippet:
            annotations[self.CONFIGURATION_SNIPPET_ANNOTATION] = "\n".join(config_snippet)
