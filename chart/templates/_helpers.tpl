{{/*
Expand the name of the chart.
*/}}
{{- define "tunnel-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | lower | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified name for a chart-level resource.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "tunnel-proxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | lower | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | lower | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | lower | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create a fully qualified name for a component resource.
*/}}
{{- define "tunnel-proxy.componentname" -}}
{{- $context := index . 0 }}
{{- $componentName := index . 1 }}
{{- $fullName := include "tunnel-proxy.fullname" $context }}
{{- printf "%s-%s" $fullName $componentName | lower | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{/*
Selector labels for a chart-level resource.
*/}}
{{- define "tunnel-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tunnel-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels for a component resource.
*/}}
{{- define "tunnel-proxy.componentSelectorLabels" -}}
{{- $context := index . 0 }}
{{- $componentName := index . 1 }}
{{- include "tunnel-proxy.selectorLabels" $context }}
app.kubernetes.io/component: {{ $componentName }}
{{- end -}}

{{/*
Common labels for all resources.
*/}}
{{- define "tunnel-proxy.commonLabels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | lower | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end }}

{{/*
Labels for a chart-level resource.
*/}}
{{- define "tunnel-proxy.labels" -}}
{{ include "tunnel-proxy.commonLabels" . }}
{{ include "tunnel-proxy.selectorLabels" . }}
{{- end }}

{{/*
Labels for a component resource.
*/}}
{{- define "tunnel-proxy.componentLabels" -}}
{{ include "tunnel-proxy.commonLabels" (index . 0) }}
{{ include "tunnel-proxy.componentSelectorLabels" . }}
{{- end -}}
