{{/*
Expand the name of the chart.
*/}}
{{- define "zenith.name" -}}
{{- default .Chart.Name .Values.nameOverride | lower | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified name for a chart-level resource.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "zenith.fullname" -}}
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
{{- define "zenith.componentname" -}}
{{- $context := index . 0 }}
{{- $componentName := index . 1 }}
{{- $fullName := include "zenith.fullname" $context }}
{{- printf "%s-%s" $fullName $componentName | lower | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{/*
Selector labels for a chart-level resource.
*/}}
{{- define "zenith.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zenith.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels for a component resource.
*/}}
{{- define "zenith.componentSelectorLabels" -}}
{{- $context := index . 0 }}
{{- $componentName := index . 1 }}
{{- include "zenith.selectorLabels" $context }}
app.kubernetes.io/component: {{ $componentName }}
{{- end -}}

{{/*
Common labels for all resources.
*/}}
{{- define "zenith.commonLabels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | lower | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end }}

{{/*
Labels for a chart-level resource.
*/}}
{{- define "zenith.labels" -}}
{{ include "zenith.commonLabels" . }}
{{ include "zenith.selectorLabels" . }}
{{- end }}

{{/*
Labels for a component resource.
*/}}
{{- define "zenith.componentLabels" -}}
{{ include "zenith.commonLabels" (index . 0) }}
{{ include "zenith.componentSelectorLabels" . }}
{{- end -}}
