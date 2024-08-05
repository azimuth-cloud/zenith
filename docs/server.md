# Deploying and configuring a Zenith server  <!-- omit in toc -->

The only supported deployment mechanism for Zenith is to use [Helm](https://helm.sh/) to
deploy on a [Kubernetes](https://kubernetes.io/) cluster.

Zenith makes heavy use of
[Kubernetes Ingress resources](https://kubernetes.io/docs/concepts/services-networking/ingress/),
and some of the optional features (e.g. the authentication and authorization callout) require
the [NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/) specifically.

See [Zenith Architecture](./architecture.md) for more detail.

This document describes the most commonly used configuration options, which will be sufficient
for the vast majority of cases. For more advanced configuration requirements, see the
[values.yaml for the chart](../chart/values.yaml) and the configuration objects for the
[sshd](../sshd/zenith/sshd/config.py) and [sync](../sync/zenith/sync/config.py) components.

## Contents  <!-- omit in toc -->

- [Prerequisites](#prerequisites)
- [Generating a signing key for the Registrar](#generating-a-signing-key-for-the-registrar)
- [Installing and upgrading Zenith](#installing-and-upgrading-zenith)
- [Specifying the IngressClass](#specifying-the-ingressclass)
- [Exposing SSHD](#exposing-sshd)
  - [Using a LoadBalancer service](#using-a-loadbalancer-service)
  - [Using a NodePort service](#using-a-nodeport-service)
- [Scaling the SSHD and registrar services](#scaling-the-sshd-and-registrar-services)
- [Transport Layer Security (TLS)](#transport-layer-security-tls)
  - [Using a pre-existing wildcard certificate](#using-a-pre-existing-wildcard-certificate)
  - [Using a wildcard certificate managed by cert-manager](#using-a-wildcard-certificate-managed-by-cert-manager)
  - [Using per-subdomain certificates managed by cert-manager](#using-per-subdomain-certificates-managed-by-cert-manager)
- [Reserved subdomains](#reserved-subdomains)
- [Authentication](#authentication)
  - [OpenID Connect](#openid-connect)
  - [External auth service](#external-auth-service)
- [Using non-standard images](#using-non-standard-images)
- [Managing resource consumption](#managing-resource-consumption)

## Prerequisites

This documentation assumes that you are already familiar with Helm and Kubernetes, and
have a Kubernetes cluster available for your Zenith deployment that has the NGINX Ingress
Controller installed.

A wildcard DNS entry must also exist for the domain that Zenith will use to expose services,
and that DNS entry should point to the Kubernetes Ingress Controller. Zenith will not
manage this for you.

For example, if Zenith is given the base domain `apps.example.cloud` then a wildcard DNS
entry must exist for `*.apps.example.cloud` that points to the Kubernetes Ingress Controller,
and services will be exposed as `subdomain1.apps.example.cloud`, `subdomain2.example.cloud`,
etc. The registrar will be exposed as `registrar.apps.example.cloud`.

If you wish to use [cert-manager](https://cert-manager.io/) to automatically request and
renew TLS certificates for Zenith services, it must be installed before you deploy Zenith.
You will also need to [configure an issuer](https://cert-manager.io/docs/configuration/)
for Zenith to consume. Zenith will not manage this for you.

## Generating a signing key for the Registrar

As mentioned in [Zenith Architecture](./architecture.md), the Zenith Registrar uses an HMAC
to ensure the data integrity and authenticity of the tokens that it issues without requiring
a database. To do this it requires a key that, if compromised, would allow an attacker to
construct a valid token for any subdomain that they like. As such, the signing key should
be kept secure and be long (at least 32-bytes is recommended) and random, e.g.:

```sh
openssl rand -hex 32
```

## Installing and upgrading Zenith

The following is a minimal Helm values file for a Zenith deployment:

```yaml
# values.yaml

common:
  ingress:
    # Services will be made available as [subdomain].apps.example.cloud
    baseDomain: apps.example.cloud
    # TLS is disabled (services will use HTTP only)
    tls:
      enabled: false

registrar:
  config:
    # The subdomain signing key
    subdomainTokenSigningKey: "<secure signing key>"
```

Zenith can then be deployed using the following commands:

```bash
# Install the Zenith Helm repository
helm repo add zenith https://azimuth-cloud.github.io/zenith

# Check for available versions
# Usually, the latest tag or latest commit to main should be used
helm search repo zenith --devel --versions

# Install Zenith using configuration from "values.yaml"
helm upgrade zenith zenith/zenith-server --version ${version} -i -f values.yaml
```

To discover the IP address for the Zenith SSHD service, use `kubectl get service` and look
at the `EXTERNAL-IP` field.

To change the configuration of your Zenith server, modify `values.yaml` and re-run the
`helm upgrade` command. To upgrade Zenith, re-run the `helm upgrade` command specifying the
version that you wish to upgrade to. In both cases, the update should happen with near-zero
downtime - the SSHD and registrar deployments are configured to allow a rolling upgrade,
however the sync component is terminated before the next iteration is started in order to
avoid races. Any existing Zenith client connections will be terminated, but if the clients
are configured to restart automatically then they should re-connect to an updated SSHD
instance automatically.

Many of the options for `values.yaml` are described in the rest of this document.

## Specifying the IngressClass

Zenith must be told what
[IngressClass](https://kubernetes.io/docs/concepts/services-networking/ingress/#ingress-class)
to use for the `Ingress` resources that it creates for services and for the registrar. This
is specified with the following:

```yaml
common:
  ingress:
    className: public
```

The default value is `nginx`, which is the name of the ingress class created when the
NGINX Ingress Controller is installed with the official Helm chart using the default
values. You can see the ingress classes available on your cluster using
`kubectl get ingressclass` (most will only have one).

## Exposing SSHD

The SSHD component is responsible for establishing secure tunnels with Zenith clients. SSH is a
TCP protocol which cannot be exposed via the Kubernetes Ingress Controller, so the primary decision
is how to expose the SSHD service outside the Kubernetes cluster.

This can be done in two ways, depending on what is available for your Kubernetes cluster.

### Using a LoadBalancer service

> If available on your Kubernetes cluster, this is the recommended mechanism for exposing SSHD
>
> It is also the default if not specified.

If supported on your Kubernetes cluster, Zenith can be configured to use a
[LoadBalancer service](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer)
to expose SSHD outside the cluster.

This creates an external TCP load-balancer with a public virtual IP, and Zenith clients connect
to the virtual IP. From there, they are routed to one of the Zenith SSHD instances.

`LoadBalancer` services are supported on most cloud providers, e.g. AWS, Azure, Google Cloud and
OpenStack (when Octavia is running). They can also be supported on bare-metal clusters using
[MetalLB](https://metallb.universe.tf/).

To configure Zenith to use a `LoadBalancer` service for SSHD, use the following:

```yaml
sshd:
  service:
    type: LoadBalancer
```

By default, Zenith will use port `22` on that load-balancer for the SSHD service. This can
be changed by specifying `sshd.service.port`, but it is not recommended or necessary.

The virtual IP address for the load-balancer can be discovered using `kubectl get service`.
Alternatively, on some cloud providers it is possible to specify the IP address to use for
the load balancer. If this is supported, you can use the following configuration:

```yaml
sshd:
  service:
    loadBalancerIP: <ip address>
```

### Using a NodePort service

As an alternative to a `LoadBalancer` service, Zenith can be configured to use a
[NodePort](https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport)
service to expose the SSHD service outside of the cluster.

For a `NodePort` service, Kubernetes allocates a port from it's node-port range (default
30000-32767) and proxies that port on each node to the service. It is up to you to set
up load-balancing - worker nodes are not typically exposed to the internet so an edge
proxy is likely to be required. It is also possible to specify a fixed port to use,
in which case it is up to you to avoid collisions with other `NodePort` services
on your cluster.

This approach works best for single-node Kubernetes clusters or bare-metal clusters
where MetalLB is not viable and a custom load-balancer is deployed.

To configure Zenith to use a `NodePort` service for SSHD, use the following:

```yaml
sshd:
  service:
    type: NodePort
    # Optionally specify a fixed node-port
    nodePort: 32222
```

## Scaling the SSHD and registrar services

The Zenith SSHD and registrar services support scaling the number of instances of each
using `sshd.replicaCount` and `registrar.replicaCount` respectively. The default for
both is `1`.

This is particularly important for SSHD because each SSHD instance can only support a
limited number of connections (small number of 1000s) because each connection requires
a unique port for the remote port forwarding.

The Zenith SSHD service can be scaled up or down by setting the number of replicas:

```yaml
sshd:
  replicaCount: 3
```

Incoming connections will be spread across the instances by the load-balancer or node-port
mechanisms (see above). When an instance dies, the clients that are connected to it will
also be terminated (the instance should be replaced by Kubernetes). For a robust system,
each client should be configured to restart when the connection is broken and will be
assigned to a new instance when it reconnects. If a service is provided by a single client
this will result in a short disruption, but the system should self-heal quickly.

Similarly, the registrar service can be scaled as follows:

```yaml
registrar:
  replicaCount: 3
```

## Transport Layer Security (TLS)

Zenith can perform TLS termination on behalf of the proxied services which, combined with the
use of SSH tunnels, ensures that traffic is encrypted for the entire journey between the end
user and the proxied service even if the service itself does not use TLS.

This can be configured by:

  1. Specifying the name of a Kubernetes secret containing a wildcard certificate for the
     Zenith base domain.
  1. Creating a cert-manager [Certificate resource](https://cert-manager.io/docs/usage/certificate/)
     that automatically requests and renews a wildcard certificate.
  1. By specifying [cert-manager](https://cert-manager.io/) annotations that will be applied to
     each `Ingress` resource that is created and instruct cert-manager to automatically
     request and renew a TLS certificate for each subdomain that is used.

The latter allows the use of cert-manager to obtain and renew TLS certificates automatically,
including from Let's Encrypt.

### Using a pre-existing wildcard certificate

If you have a pre-existing wildcard TLS certificate, you first need to create a TLS secret
containing the certificate and private key. The certificate file must include the
*full certificate chain* in order, with the most specific certificate at the top and the root
CA at the bottom:

```bash
kubectl create secret tls zenith-wildcard-tls --cert=path/to/cert/file --key=path/to/key/file
```

Then configure Zenith to use that secret for the `Ingress` resources it creates:

```yaml
common:
  ingress:
    tls:
      secretName: zenith-wildcard-tls
```

> **WARNING**
>
> It is your responsibility to check for the expiry of the wildcard certificate and renew it
> when required.

### Using a wildcard certificate managed by cert-manager

If you use one of the
[supported DNS providers](https://cert-manager.io/docs/configuration/acme/dns01/#supported-dns01-providers),
cert-manager can automatically request and renew a wildcard certificate from Let's Encrypt
using the [DNS-01 challange type](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge).

To do this, you first need to create an issuer that uses the DNS-01 challenge type,
then create a [Certificate resource](https://cert-manager.io/docs/usage/certificate/) that
refers to that issuer:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: apps-example-cloud
spec:
  # The issuer to use
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: letsencrypt-dns01
  # The signed certificate will be placed in this secret
  secretName: zenith-wildcard-tls
  # The DNS name
  commonName: "*.example.cloud"
  dnsNames:
    - example.cloud
    - "*.example.cloud"
```

This will result in cert-manager populating the secret `zenith-wildcard-tls` with the signed
wildcard certificate, then keeping it renewed from then on. Zenith can then be configured
to use this secret in the same way as for a manually-issued certificate:

```yaml
common:
  ingress:
    tls:
      secretName: zenith-wildcard-tls
```

### Using per-subdomain certificates managed by cert-manager

When cert-manager is installed and an issuer is configured, it is possible to specify
annotations that will be added to every `Ingress` resource made by Zenith. These annotations
instruct cert-manager to dynamically request a TLS certificate for the `Ingress` resource.

To configure annotations for the `Ingress` resources created by Zenith, use the following:

```yaml
common:
  ingress:
    tls:
      annotations:
        cert-manager.io/cluster-issuer: name-of-issuer
```

This mechanism can be used to consume certificates issued by Let's Encrypt using the
[HTTP-01 challenge type](https://letsencrypt.org/docs/challenge-types/#http-01-challenge).

> **WARNING**
>
> Let's Encrypt applies a [rate limit](https://letsencrypt.org/docs/rate-limits/) on the
> issuance of certificates that, at the time of writing, allows 50 certificates per week
> per *Registered Domain*. This means that even if Zenith has been given `apps.example.cloud`,
> the limit would apply to the whole of `example.cloud`.

## Reserved subdomains

Zenith can be configured so that some subdomains are reserved and hence not available
for Zenith clients to use. For example, the Azimuth portal uses this to reserve the
subdomain used to expose the portal interface to prevent a malicious Zenith client
replacing the portal interface with their own.

To configure reserved subdomains, use the following configuration:

```yaml
registrar:
  config:
    reservedSubdomains: [portal, metrics]
```

## Authentication

Zenith is capable of enforcing authentication and authorization for incoming requests using
either OpenID Connect or an external auth service.

### OpenID Connect

Zenith is able to natively apply [OpenID Connect (OIDC)](https://openid.net/connect/)
authentication, with group-based authorization, for proxied services. This is implemented
using [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy).

Where clients have a specific OIDC issuer and client credentials that they want to use,
they can specify those when initiating a connection (see
[Configuring the Zenith client](./client.md)). If given, client-specified credentials
are used even if discovery credentials are also present.

However Zenith also supports discovery of OIDC credentials on the server side for the
case where the server wishes to impose OIDC authentication (except where the client
opts out of authentication completely). This mode allows an external controller to place
secrets in the `zenith-services` namespace containing OIDC credentials for a service:

```yaml
apiVersion: v1
kind: Secret
metadata:
  # The name is important
  name: oidc-discovery-{service subdomain}
  namespace: zenith-services
stringData:
  issuer-url: https://identity.company.org/oidc
  client-id: <client id>
  client-secret: <client secret>
  # JSON-encoded list of group names that are permitted to access the service
  allowed-groups: |
    [
      "group1",
      "group2
    ]
```

The client must be created with `http(s)://{service FQDN}/_oidc/callback` as the redirect
URI.

OIDC discovery is off by default. To enable it, use the following configuration:

```yaml
sync:
  kubernetes:
    ingress:
      oidc:
        discoveryEnabled: true
```

> **WARNING**
>
> When OIDC credential discovery is enabled, the creation of ingress resources for a
> service is delayed until the OIDC credential becomes available. This means that if
> the controller that writes the discovery secrets suffers a problem, services that
> are using OIDC credential discovery will remain unavailable until the problem is
> resolved.
>
> The unavailability of an OIDC credential for one service _will not_ block other
> services from becoming available.


### External auth service

To support authentication methods other than OpenID Connect, Zenith is able to enforce
authentication and authorization for incoming requests by consuming a pre-existing
external auth service using an
[auth subrequest](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html).

When external auth is configured, the `Ingress` resources that Zenith creates are
annotated with information that tells NGINX to make an auth subrequest to the external
auth service. The auth subrequest consists of the same request body and headers as the
original request, and the auth service should make a decision about whether the request
is permitted and return either a 401 (if no or invalid credentials are given), 403 (if
valid credentials are given but permission is denied) or 200 (if the request should be
allowed to proceed).

External auth is enabled by specifying the URL of the auth service. If the auth service
is running in the same Kubernetes cluster, it can be a fully-qualified service URL
(because the verification request is a subrequest coming from the NGINX Ingress
Controller, not from the user's browser):

```yaml
sync:
  config:
    kubernetes:
      ingress:
        externalAuth:
          url: http://auth-service.other-namespace.svc.cluster.local:8080/auth/verify/
```

It is also possible to specify the URL that the user should be redirected to if the
auth service returns a 401, indicating that credentials are required. This URL is
returned to the user's browser as a redirect, so it must be an **external** URL even
if the auth service is also running in Kubernetes. It receives the original URL as a
URL parameter (default `next`) so that it can redirect back when the user has
authenticated:

```yaml
sync:
  config:
    kubernetes:
      ingress:
        externalAuth:
          url: ...
          signinUrl: https://auth.apps.example.cloud/login
          # The URL parameter that will contain the original URL
          # when the user is redirected (default "next")
          nextUrlParam: next_url
```

## Using non-standard images

It is possible to specify different images used for the Zenith components, for example if
the Zenith images are mirrored into an internal registry:

```yaml
sync:
  image:
    repository: internal.repo/zenith/zenith-sync
    # The tag defaults to the appVersion of the chart
    tag: <valid tag>

sshd:
  image:
    repository: internal.repo/zenith/zenith-sshd
    # The tag defaults to the appVersion of the chart
    tag: <valid tag>

registrar:
  image:
    repository: internal.repo/zenith/zenith-registrar
    # The tag defaults to the appVersion of the chart
    tag: <valid tag>
```

## Managing resource consumption

In a production environment, it is important to constrain the resources available to each
container in order to prevent a rogue container starving other workloads on the cluster,
or even taking down a node.

In Kubernetes, this is done using
[resource requests and limits](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).
These can be set for the Zenith components using the Helm chart (the following values
are just an example and not a recommendation!):

```yaml
sync:
  resources:
    requests:
      cpu: 500m
      memory: 128Mi
    limits:
      cpu: 1000m
      memory: 1Gi

sshd:
  resources:
    requests:
      cpu: 500m
      memory: 128Mi
    limits:
      cpu: 1000m
      memory: 1Gi

registrar:
  resources:
    requests:
      cpu: 200m
      memory: 64Mi
    limits:
      cpu: 1000m
      memory: 512Mi
```

Alternatively, you can use the
[Vertical Pod Autoscaler](https://github.com/kubernetes/autoscaler/tree/master/vertical-pod-autoscaler)
to set these values automatically based on observed usage.
