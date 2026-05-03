{{/*
Expand the name of the chart.
*/}}
{{- define "dragon-scale.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dragon-scale.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "dragon-scale.labels" -}}
helm.sh/chart: {{ include "dragon-scale.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: dragon-scale
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{- define "dragon-scale.selectorLabels" -}}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Generate image reference for a service.
Usage: {{ include "dragon-scale.image" (dict "service" .Values.authService "global" .Values) }}
*/}}
{{- define "dragon-scale.image" -}}
{{- $registry := .global.image.registry -}}
{{- $repo := .global.image.repository -}}
{{- $tag := .global.image.tag -}}
{{- printf "%s/%s/%s:%s" $registry $repo .service.image.name $tag -}}
{{- end }}

{{/*
Common environment variables for all backend services.
*/}}
{{- define "dragon-scale.commonEnv" -}}
- name: REDIS_URL
  value: "redis://{{ include "dragon-scale.fullname" . }}-redis-master:6379"
- name: KAFKA_BOOTSTRAP_SERVERS
  value: "{{ include "dragon-scale.fullname" . }}-kafka:9092"
- name: AUTH_SERVICE_URL
  value: "http://{{ include "dragon-scale.fullname" . }}-auth-service:5000"
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: dragon-scale-db-credentials
      key: connection-string
- name: JWT_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: dragon-scale-auth-secrets
      key: jwt-secret-key
{{- if .Values.observability.opentelemetry.enabled }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ .Values.observability.opentelemetry.collectorEndpoint | quote }}
- name: OTEL_SERVICE_NAME
  value: "$(SERVICE_NAME)"
{{- end }}
{{- end }}
