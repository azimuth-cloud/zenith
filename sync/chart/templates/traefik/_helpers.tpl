{{/*
Annotations for the Traefik ingress resource.
*/}}
{{- define "zenith-service.traefik.ingress.annotations" -}}
{{ toYaml .Values.ingress.annotations }}
traefik.ingress.kubernetes.io/service.serversscheme: {{ .Values.protocol }}
{{- if .Values.readTimeout }}
traefik.ingress.kubernetes.io/service.serverstransport: {{ printf "%s-%s-transport@kubernetescrd" .Release.Namespace .Release.Name }}
{{- end }}
{{- if .Values.global.secure }}
{{- include "zenith-service.traefik.ingress.tls.annotations" . }}
{{- end }}
{{- $middlewares := include "zenith-service.traefik.ingress.middlewares" . }}
{{- if $middlewares }}
traefik.ingress.kubernetes.io/router.middlewares: {{ $middlewares | quote }}
{{- end }}
{{- end }}

{{/*
Annotations for TLS (cert-manager passthrough + client CA).
*/}}
{{- define "zenith-service.traefik.ingress.tls.annotations" -}}
{{-
  if and
    (not .Values.ingress.tls.terminatedAtProxy)
    (not .Values.ingress.tls.existingCertificate.cert)
}}
{{- with .Values.ingress.tls.annotations }}
{{ toYaml . }}
{{- end }}
{{- end }}
{{- if .Values.ingress.tls.clientCA }}
traefik.ingress.kubernetes.io/router.tls.options: {{ printf "%s-%s-client-ca@kubernetescrd" .Release.Namespace .Release.Name }}
{{- end }}
{{- end }}

{{/*
Builds the comma-separated list of Traefik middlewares to attach to the router.
*/}}
{{- define "zenith-service.traefik.ingress.middlewares" -}}
{{- $middlewares := list -}}
{{- if and .Values.global.secure .Values.ingress.tls.clientCA -}}
{{- $middlewares = append $middlewares (printf "%s-%s-client-cert@kubernetescrd" .Release.Namespace .Release.Name) -}}
{{- end -}}
{{- if .Values.externalAuth.enabled -}}
{{- if or .Values.externalAuth.requestHeaders .Values.externalAuth.params -}}
{{- $middlewares = append $middlewares (printf "%s-%s-external-auth-headers@kubernetescrd" .Release.Namespace .Release.Name) -}}
{{- end -}}
{{- if .Values.externalAuth.signinUrl -}}
{{- $middlewares = append $middlewares (printf "%s-%s-external-auth-errors@kubernetescrd" .Release.Namespace .Release.Name) -}}
{{- end -}}
{{- $middlewares = append $middlewares (printf "%s-%s-external-auth@kubernetescrd" .Release.Namespace .Release.Name) -}}
{{- end -}}
{{- if and .Values.oidc.enabled (not .Values.oidc.ingress.enabled) -}}
{{- $middlewares = append $middlewares (printf "%s-%s-oidc-errors@kubernetescrd" .Release.Namespace .Release.Name) -}}
{{- $middlewares = append $middlewares (printf "%s-%s-oidc-auth@kubernetescrd" .Release.Namespace .Release.Name) -}}
{{- end -}}
{{- join "," $middlewares -}}
{{- end -}}
