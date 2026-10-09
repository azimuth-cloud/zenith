{{/*
Selector labels for a chart-level resource.
*/}}
{{- define "zenith-service.selectorLabels" -}}
zenith.stackhpc.com/service-name: {{ .Release.Name }}
{{- end }}

{{/*
Labels for a chart-level resource.
*/}}
{{- define "zenith-service.labels" -}}
helm.sh/chart: {{
  printf "%s-%s" .Chart.Name .Chart.Version |
    replace "+" "_" |
    lower |
    trunc 63 |
    trimSuffix "-" |
    trimSuffix "." |
    trimSuffix "_"
}}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{ include "zenith-service.selectorLabels" . }}
{{- end }}

{{/*
Annotations for the ingress resource.
*/}}
{{- define "zenith-service.ingress.annotations" -}}
{{ toYaml .Values.ingress.annotations }}
nginx.ingress.kubernetes.io/backend-protocol: {{ quote .Values.protocol }}
{{- with .Values.readTimeout }}
nginx.ingress.kubernetes.io/proxy-read-timeout: {{ int64 . | quote }}
{{- end }}
{{- if .Values.global.secure }}
{{- include "zenith-service.ingress.tls.annotations" . }}
{{- end }}
{{- if .Values.externalAuth.enabled }}
{{- include "zenith-service.ingress.auth.external.annotations" . }}
{{- end }}
{{- if .Values.oidc.enabled }}
{{- include "zenith-service.ingress.auth.oidc.annotations" . }}
{{- end }}
{{- end }}

{{/*
Annotations for TLS.
*/}}
{{- define "zenith-service.ingress.tls.annotations" -}}
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
nginx.ingress.kubernetes.io/auth-tls-secret: "{{ .Release.Namespace }}/{{ include "zenith-service.ingress.tls.clientCASecretName" . }}"
nginx.ingress.kubernetes.io/auth-tls-verify-client: optional
nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream: "true"
{{- end }}
{{- end }}

{{/*
Annotations for external auth.
*/}}
{{- define "zenith-service.ingress.auth.external.annotations" -}}
{{- with .Values.externalAuth }}
nginx.ingress.kubernetes.io/auth-url: {{ .url | required "external auth URL is required" | quote }}
{{- if .signinUrl }}
nginx.ingress.kubernetes.io/auth-signin: {{ include "zenith-service.ingress.auth.external.signinUrl" . | quote }}
{{- end }}
{{- if or .requestHeaders .params }}
nginx.ingress.kubernetes.io/auth-snippet: |
  {{- range $k, $v := .requestHeaders }}
  proxy_set_header {{ $k }} {{ $v }};
  {{- end }}
  {{- range $k, $v := .params }}
  proxy_set_header {{ $.paramHeaderPrefix }}{{ $k }} {{ $v }};
  {{- end }}
{{- end }}
{{- if .responseHeaders }}
nginx.ingress.kubernetes.io/auth-response-headers: {{ join "," .responseHeaders | quote }}
{{- end }}
{{- end }}
{{- end }}

{{/*
The signin URL for external auth, including the parameter for the original URL.
*/}}
{{- define "zenith-service.ingress.auth.external.signinUrl" -}}
{{- $query := get (urlParse .signinUrl) "query" }}
{{- if regexMatch (printf "(^|&)%s=" (regexQuoteMeta .nextUrlParam)) $query }}
{{- .signinUrl }}
{{- else }}
{{-
  printf "%s%s%s=$scheme://$best_http_host$escaped_request_uri"
    .signinUrl
    (ternary "&" "?" (contains "?" .signinUrl))
    .nextUrlParam
}}
{{- end }}
{{- end }}

{{/*
Annotations for OIDC auth.
*/}}
{{- define "zenith-service.ingress.auth.oidc.annotations" -}}
{{- $scheme := ternary "https" "http" .Values.global.secure }}
{{- $host := include "zenith-service.ingress.host" . }}
{{- $oidcReleaseName := printf "%s-oidc" .Release.Name }}
{{- $prefix := tpl (index .Values.oidc.extraArgs "proxy-prefix") . }}
nginx.ingress.kubernetes.io/auth-url: >-
  http://{{ $oidcReleaseName }}.{{ .Release.Namespace }}.svc.cluster.local{{ $prefix }}/auth
nginx.ingress.kubernetes.io/auth-signin: >-
  {{ $scheme }}://{{ $host }}{{ $prefix }}/start?rd=$escaped_request_uri&$args
{{- with .Values.oidc.alphaConfig.configData.injectResponseHeaders }}
nginx.ingress.kubernetes.io/auth-response-headers: >-
  {{ range $i, $rh := . }}{{ if $i }},{{ end }}{{ $rh.name }}{{ end }}
{{- end }}
{{- /*
  Forward the cookie set by the OAuth2 proxy when it refreshes a session in the auth
  subrequest.

  Only a single Set-Cookie header can be forwarded this way.
  Use the Valkey session store to prevent oauth2-proxy splitting the cookie.
*/}}
nginx.ingress.kubernetes.io/configuration-snippet: |
  auth_request_set $auth_cookie $upstream_http_set_cookie;
  add_header Set-Cookie $auth_cookie;
{{- end }}

{{/*
Name for the TLS secret.
*/}}
{{- define "zenith-service.ingress.tls.secretName" -}}
{{- if .Values.ingress.tls.secretName }}
{{- .Values.ingress.tls.secretName }}
{{- else }}
{{- printf "tls-%s" .Release.Name }}
{{- end }}
{{- end }}

{{/*
Name for the TLS client CA secret.
*/}}
{{- define "zenith-service.ingress.tls.clientCASecretName" -}}
{{- printf "tls-client-ca-%s" .Release.Name }}
{{- end }}

{{/*
The host to use for ingress resources.
*/}}
{{- define "zenith-service.ingress.host" -}}
{{- $baseDomain := required "baseDomain is required" .Values.global.baseDomain -}}
{{- $subdomain := required "subdomain is required" .Values.global.subdomain -}}
{{-
  ternary
    $baseDomain
    (printf "%s.%s" $subdomain $baseDomain)
    .Values.global.subdomainAsPathPrefix
-}}
{{- end }}

{{/*
The path prefix to use for ingress resources.
*/}}
{{- define "zenith-service.ingress.pathPrefix" -}}
{{- $baseDomain := required "baseDomain is required" .Values.global.baseDomain -}}
{{- $subdomain := required "subdomain is required" .Values.global.subdomain -}}
{{- ternary (printf "/%s" $subdomain) "/" .Values.global.subdomainAsPathPrefix -}}
{{- end }}
