# Zenith Architecture  <!-- omit in toc -->

This document describes the architecture of Zenith in detail.

> **WARNING**
>
> Although still broadly relevant, some parts of this document are out-of-date.
>
> In particular, Consul has been replaced as the store by a Kubernetes CRD.

Zenith has a client-server architecture in which the client and server collaborate to
establish a secure tunnel over which traffic is proxied in a controlled way from the
internet to a service that would not otherwise be exposed to the internet. This allows
services that are behind NAT or a firewall to be exposed to end-users while only
being bound locally. Those services can also (optionally) benefit from TLS termination
and authentication/authorization performed by Zenith at the proxy.

Zenith is mostly composed of industry-standard software and protocols such as
[OpenSSH](https://www.openssh.com/), [Hashicorp Consul](https://www.consul.io/) and the
[NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/), glued together
with a small amount of custom code and deployed using [Kubernetes](https://kubernetes.io/).

## Contents  <!-- omit in toc -->

- [Architecture Diagram](#architecture-diagram)
- [Establishing a proxied service](#establishing-a-proxied-service)
- [Allocated port detection](#allocated-port-detection)
- [Registrar tokens](#registrar-tokens)
- [Why not use Consul Service Sync?](#why-not-use-consul-service-sync)
- [SSHD hardening](#sshd-hardening)

## Architecture Diagram

This diagram shows the components in the Zenith Architecture. Components are colour-coded
to show their ownership in four classes:

  * **Zenith Component**: The component is composed of custom Zenith code.
  * **Managed Component**: The component is managed as part of a Zenith installation.
  * **Kubernetes Component**: The component is part of or managed by the Kubernetes cluster.
  * **External Component**: The component is external to and not managed by Zenith.

Additionally, some optional components are also shown on the diagram.

![Zenith Architecture Diagram](./zenith-architecture.png?raw=true)

## Establishing a proxied service

The following describes the flow between the components that establish an instance of a
proxied service:

  1. The broker reserves a subdomain with the Zenith registrar and receives a single-use token
     that can be used to associate SSH public keys with that subdomain.
  2. The broker communicates the token to the client. The delivery mechanism is out-of-scope
     for Zenith and will be different for each use case.
  3. The Zenith client `bootstrap` command generates an SSH keypair (if required) and uploads
     the public key to the registrar using the given token. This associates the public key
     with the subdomain.
  4. The Zenith client `connect` command is launched using the SSH keypair from step (3).
  5. The `connect` command spawns an SSH client process that connects to the SSHD component
     of a Zenith server.
       * The SSH client requests a dynamically-allocated remote forwarded port from SSHD by using
         `0` as the remote port number with the `-R` option, i.e.
         `ssh -R 0:${service_host}:${service_port}`.
       * The `stdin/out/err` streams of the SSH client process are connected to pipes that the
         `connect` command controls.
  6. The SSH connection is assigned to an SSHD instance by the TCP load-balancer. This allocation
     persists for the duration of the SSH connection.
  7. SSHD invokes the `authorized-keys` script, which sends the public key used for the connection
     to the registrar for verification.
  8. The registrar responds with the associated subdomain for the public key, or an error
     if the public key is not known.
  9. The `authorized-keys` script indicates to SSHD whether to accept the public key and, if
     the key is accepted, the invocation of the `tunnel-init` script to use (including the
     subdomain).
  10. SSHD responds to the SSH client with the allocated port on `stderr`, which is read by the
      client `connect` command.
  11. SSHD launches the `tunnel-init` script using the invocation returned by the `authorized-keys`
      script. `stdin/out/err` are connected to the SSH client process.
  12. The `connect` command passes the tunnel configuration, including the allocated port, to
      the `tunnel-init` script on `stdin`.
  13. The `tunnel-init` script creates a service instance in Consul that associates the subdomain
      for the public key with the pod IP of the allocated SSHD instance and the allocated port for
      the tunnel.
      * There can be multiple instances associated with the same subdomain. They can either
        share an SSH key or multiple SSH public keys can be registered for a subdomain.
  14. The sync component of the Zenith server is notified of the change in Consul.
  15. The sync component creates or updates the `Endpoints`, `Service` and `Ingress` resources
      in Kubernetes to match the current service instances for the subdomain.
      * Each subdomain has one of each resource.
      * Each proxied service instance corresponds to a single entry in the `Endpoints`
        resource for the subdomain.
      * See [Services without selectors](https://kubernetes.io/docs/concepts/services-networking/service/#services-without-selectors)
        for more information on how this works in Kubernetes.
  16. Traffic can now flow from the user to the proxied service via the Ingress Controller
      and SSH tunnel.

## Allocated port detection

Steps 10, 11 and 12, where the allocated port is returned by SSHD to the SSH client and then passed
back to the `tunnel-init` script via the `connect` command, are necessary because the allocated
port number is not made available to the spawned `tunnel-init` script by SSHD.

This obviously places a lot of trust in the client to report the allocated port correctly. It
would be preferable to detect the port from the `tunnel-init` script, but this appears to be very
difficult, and probably impossible without root.

Instead, we put in place some mitigations to prevent a malicious client from crafting a tunnel that
allows them to receive traffic that is not intended for them:

  * Clients are encouraged to use dynamically-allocated ports.
      * This is enforced when using the Zenith client.
      * This makes the allocated port for a client harder to guess, and so it is more difficult
        for a malicious client to connect their subdomain to the port for another client in order
        to access the proxied service.
  * Each subdomain is associated with a particular set of public keys using a single-use token.
      * Clients are not able to request any subdomain they like.
      * This prevents a malicious client from binding to a subdomain other than the one they
        were allocated in order to spoof another service. In order to do so, the malicious client
        would need to compromise either the single-use token before it is used by the genuine
        client or the private key of the genuine client (which never leaves the client), both of
        which are very unlikely.
  * Only allow a subdomain to be bound to a port that is listening.
      * This prevents a malicious client from pre-binding its allocated subdomain to a port that
        is not yet in use in the hope of intercepting traffic in the future.
  * Only allow one subdomain to be bound to each SSHD instance/port combination.
      * This prevents a malicious client from binding an additional subdomain that is allocated
        to them to an existing tunnel in order to access that service.
  * SSHD is configured so that the `tunnel-init` script is the only command that can be run.
      * This prevents a malicious client from running another command to collect information
        about the bound ports or to contact Consul.
  * SSHD is configured so that it only permits remote port forwarding, not local or dynamic
    port forwarding (see
    [SSH port forwarding](https://help.ubuntu.com/community/SSH/OpenSSH/PortForwarding)).
      * This prevents a malicious client from setting up a local forwarded port to the
        bound port for another service and sending traffic directly to it, bypassing the
        Zenith proxying and any associated authentication.

## Registrar tokens

The tokens that are returned by the registrar when a subdomain is reserved are not stored anywhere.
Instead, the subdomain is present in the token but the token also includes a
[hash-based message authentication code (HMAC)](https://en.wikipedia.org/wiki/HMAC) which can
be used to verify both the data integrity (i.e. has the subdomain been changed) and authenticity
(i.e. was the token issued by the registrar) of the token.

The tokens are made single-use by using the subdomain a bit like a mutex in Consul. When a
subdomain is reserved, a record for the subdomain is created in Consul with a value of `0` -
the presence of this record prevents the subdomain from being reserved again. When the
registrar token is used to register public keys for a subdomain, the value of this subdomain
records is flipped from `0` to `1` at the same time as the public keys are stored. Only the
first client to perform this operation will succeed, hence the tokens are single-use. This
is acheived using [transactions](https://www.consul.io/api-docs/txn) and
[check-and-set (CAS)](https://www.consul.io/commands/kv/put#cas) operations in Consul.

## Why not use Consul Service Sync?

Consul does have a [Service Sync component](https://www.consul.io/docs/k8s/service-sync) that
will synchronise Consul services with Kubernetes services, however this is implemented using
[ExternalName services](https://kubernetes.io/docs/concepts/services-networking/service/#externalname)
rather than `Endpoints`.

This is not suitable for Zenith because the port numbers that are assigned for the remote
forwarded ports are not predictable. Also, in the case where multiple instances of a proxied
service are registered for the same subdomain they will be allocated different port numbers.
Using `Endpoints` rather than `ExternalName` services allows this to work.

## SSHD hardening

Zenith relies heavily on the SSH protocol to establish secure tunnels. However we want to
prevent the abuse of the power of SSH by malicious clients. To do this, SSHD is hardened
in several ways:

  * Disabling all unnecessary features, e.g. agent forwarding, X11 forwarding, local and
    dynamic port forwarding.
  * Only allowing connections from clients whose public key has been registered with the
    registrar using a single-use token.
  * Using `ForceCommand` to force the `tunnel-init` script to run on every connection.
  * Using `AllowUsers` to permit connections only for a single, non-root user (called `zenith`).
  * Running SSHD as the `zenith` user (so that changing to another user is not possible).
  * Setting the login shell of the `zenith` user to [rbash](https://en.wikipedia.org/wiki/Restricted_shell),
    a restricted shell, so that the operations that can be performed are restricted even
    if `ForceCommand` is bypassed (which shouldn't happen anyway!).
  * Only forwarding whitelisted environment variables into spawned connections that are known
    to be part of the Zenith configuration.
  * Running the SSHD containers with a tight
    [security context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
    that:
      * Enforces a read-only root file-system, so that unexpected configuration changes cannot occur.
      * Enforces that the container runs as a non-root user.
      * Drops all
        [Linux capabilities](https://linux-audit.com/linux-capabilities-hardening-linux-binaries-by-removing-setuid/)
        from the container.
