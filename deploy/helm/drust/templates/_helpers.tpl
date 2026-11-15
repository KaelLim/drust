{{- define "drust.svcName" -}}drust{{- end -}}
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
{{- define "drust.backupSecretName" -}}{{ if .Values.backup.external.create }}{{ .Release.Name }}-backup-secret{{ else }}{{ required "backup.external.existingSecret required when backup.external.create=false" .Values.backup.external.existingSecret }}{{ end }}{{- end -}}
{{- define "backup.prefix" -}}{{ .Values.backup.external.pathPrefix | default .Release.Namespace }}{{- end -}}
{{- define "litestream.configName" -}}{{ .Release.Name }}-litestream{{- end -}}
{{- define "backupMirror.selectorLabels" -}}
app.kubernetes.io/name: backup-mirror
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- /* rclone remote "bk" (the external backup S3), configured only from env: no config
       file, and the keys arrive by secretKeyRef, never inside a URL. Shared by the
       litestream-enumerate init container and the backup-mirror CronJob. */ -}}
{{- define "drust.rcloneBackupRemote" -}}
- { name: RCLONE_CONFIG_BK_TYPE, value: s3 }
- { name: RCLONE_CONFIG_BK_PROVIDER, value: Other }
- { name: RCLONE_CONFIG_BK_ENDPOINT, value: {{ .Values.backup.external.endpoint | quote }} }
- { name: RCLONE_CONFIG_BK_REGION, value: {{ .Values.backup.external.region | quote }} }
- { name: RCLONE_CONFIG_BK_FORCE_PATH_STYLE, value: {{ .Values.backup.external.forcePathStyle | quote }} }
- name: RCLONE_CONFIG_BK_ACCESS_KEY_ID
  valueFrom: { secretKeyRef: { name: {{ include "drust.backupSecretName" . }}, key: backup-s3-access-key } }
- name: RCLONE_CONFIG_BK_SECRET_ACCESS_KEY
  valueFrom: { secretKeyRef: { name: {{ include "drust.backupSecretName" . }}, key: backup-s3-secret-key } }
{{- end -}}
{{- define "publicProxy.selectorLabels" -}}
app.kubernetes.io/name: public-proxy
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "rustfs.svcName" -}}rustfs{{- end -}}
{{- /* The bundled RustFS's S3 endpoint, used by drust, public-proxy and backup-mirror. */ -}}
{{- define "drust.storeEndpoint" -}}http://{{ include "rustfs.svcName" . }}.{{ .Release.Namespace }}.svc:9000{{- end -}}
{{- define "rustfs.selectorLabels" -}}
app.kubernetes.io/name: rustfs
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "rustfsInit.selectorLabels" -}}
app.kubernetes.io/name: rustfs-init
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
