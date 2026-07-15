{{- define "drust.svcName" -}}drust{{- end -}}
{{- define "minio.svcName" -}}minio{{- end -}}
{{- define "minio.endpoint" -}}http://minio.{{ .Release.Namespace }}.svc:9000{{- end -}}
{{- define "drust.tlsSecret" -}}{{ .Values.ingress.tls.secretName | default (printf "%s-tls" .Release.Name) }}{{- end -}}
{{- define "drust.secretName" -}}{{ if .Values.secrets.create }}{{ .Release.Name }}-secret{{ else }}{{ required "secrets.existingSecret required when secrets.create=false" .Values.secrets.existingSecret }}{{ end }}{{- end -}}
{{- define "drust.labels" -}}
app.kubernetes.io/name: drust
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: drust-{{ .Chart.Version }}
{{- end -}}
{{- define "drust.selectorLabels" -}}
app.kubernetes.io/name: drust
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "minio.selectorLabels" -}}
app.kubernetes.io/name: minio
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
