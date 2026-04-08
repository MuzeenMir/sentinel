{{/*
Expand the name of the chart.
*/}}
{{- define "sentinel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sentinel.fullname" -}}
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

{{- define "sentinel.labels" -}}
helm.sh/chart: {{ include "sentinel.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: sentinel
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{- define "sentinel.selectorLabels" -}}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Generate image reference for a service.
Usage: {{ include "sentinel.image" (dict "service" .Values.authService "global" .Values) }}
*/}}
{{- define "sentinel.image" -}}
{{- $registry := .global.image.registry -}}
{{- $repo := .global.image.repository -}}
{{- $tag := .global.image.tag -}}
{{- printf "%s/%s/%s:%s" $registry $repo .service.image.name $tag -}}
{{- end }}

{{/*
Common environment variables for all backend services.
*/}}
{{- define "sentinel.commonEnv" -}}
- name: REDIS_URL
  value: "redis://{{ include "sentinel.fullname" . }}-redis-master:6379"
- name: KAFKA_BOOTSTRAP_SERVERS
  value: "{{ include "sentinel.fullname" . }}-kafka:9092"
- name: AUTH_SERVICE_URL
  value: "http://{{ include "sentinel.fullname" . }}-auth-service:5000"
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: sentinel-db-credentials
      key: connection-string
- name: JWT_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: sentinel-auth-secrets
      key: jwt-secret-key
{{- if .Values.observability.opentelemetry.enabled }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ .Values.observability.opentelemetry.collectorEndpoint | quote }}
- name: OTEL_SERVICE_NAME
  value: "$(SERVICE_NAME)"
{{- end }}
{{- end }}
