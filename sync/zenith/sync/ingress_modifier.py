INGRESS_MODIFIERS_ENTRY_POINT_GROUP = "zenith.sync.ingress_modifiers"


class IngressModifier:
    """
    Base class for an ingress modifier.
    """
    def configure_backend_protocol(self, ingress, protocol):
        """
        Applies any configuration required to enable the specified backend protocol
        for the specified ingress. The ingress should be modified in-place.
        """
        raise NotImplementedError


class NginxIngressModifier(IngressModifier):
    """
    Ingress modifier for the Nginx Ingress Controller.
    """
    BACKEND_PROTOCOL_ANNOTATION = "nginx.ingress.kubernetes.io/backend-protocol"

    def configure_backend_protocol(self, ingress, protocol):
        ingress["metadata"]["annotations"][self.BACKEND_PROTOCOL_ANNOTATION] = protocol.upper()
