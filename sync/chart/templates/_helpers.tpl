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
{{- /*
  With OIDC, the ingress forwards to the OAuth2 proxy, which listens on HTTP and
  forwards authenticated requests to the service using the service protocol
*/}}
nginx.ingress.kubernetes.io/backend-protocol: {{ ternary "http" .Values.protocol .Values.oidc.enabled | quote }}
{{- with .Values.readTimeout }}
nginx.ingress.kubernetes.io/proxy-read-timeout: {{ int64 . | quote }}
{{- end }}
{{- if .Values.global.secure }}
{{- include "zenith-service.ingress.tls.annotations" . }}
{{- end }}
{{- if .Values.externalAuth.enabled }}
{{- include "zenith-service.ingress.auth.external.annotations" . }}
{{- end }}
{{- if and .Values.oidc.enabled .Values.oidc.provider.loginURLParameters }}
{{- include "zenith-service.ingress.oidc.annotations" . }}
{{- end }}
{{- end }}

{{/*
Oauth2-proxy ignores query parameters on the request (https://github.com/oauth2-proxy/oauth2-proxy/pull/2316).
This means that parameters in loginURLParameters, e.g. kc_idp_hint, are not forwarded to
the IdP.

To fix this, we redirect requests that have one of the parameters but no session cookie
to the start endpoint with the query parameters of the request.

To ensure we never get a loop, return the user to the path without query strings.

These directives are supported by ingress-nginx and Traefik's NGINX compatibility.
*/}}
{{- define "zenith-service.ingress.oidc.annotations" -}}
{{- $prefix := tpl (index .Values.oidc.extraArgs "proxy-prefix") . }}
{{- $cookieName := index .Values.oidc.extraArgs "cookie-name" | default "_oauth2_proxy" }}
{{- range (list $cookieName (printf "%s_0" $cookieName)) }}
{{- if not (regexMatch "^[A-Za-z0-9_]+$" .) }}
{{- fail (printf "cookie name %q cannot be used in an NGINX variable" .) }}
{{- end }}
{{- end }}
nginx.ingress.kubernetes.io/configuration-snippet: |
  set $zenith_oidc_start "";
  {{- range .Values.oidc.provider.loginURLParameters }}
  {{- if not (regexMatch "^[A-Za-z0-9_]+$" .name) }}
  {{- fail (printf "login URL parameter %q cannot be used in an NGINX variable" .name) }}
  {{- end }}
  if ($arg_{{ .name }}) { set $zenith_oidc_start "1"; }
  {{- end }}
  {{- /* The session cookie may be split. */}}
  if ($cookie_{{ $cookieName }}) { set $zenith_oidc_start ""; }
  if ($cookie_{{ $cookieName }}_0) { set $zenith_oidc_start ""; }
  {{- /* The path of the request, without the query parameters, still URL-encoded */}}
  if ($request_uri ~ "^([^?]*)") { set $zenith_oidc_rd $1; }
  if ($zenith_oidc_start) { return 302 {{ $prefix }}/start?rd=$zenith_oidc_rd&$args; }
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
