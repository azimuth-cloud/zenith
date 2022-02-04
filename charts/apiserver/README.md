# zenith-apiserver

This Helm chart is specifically designed to be used with `helm template` to render
a static pod definition which can be used to proxy the Kubernetes API server using
Zenith in a `kubeadm` based cluster.

The rendered configmap contains the files that should be placed in `/etc/zenith`.
