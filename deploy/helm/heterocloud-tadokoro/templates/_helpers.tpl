{{- define "tadokoro.name" -}}heterocloud-tadokoro{{- end -}}
{{- define "tadokoro.labels" -}}
app.kubernetes.io/name: {{ include "tadokoro.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
{{- define "tadokoro.selector" -}}
app.kubernetes.io/name: {{ include "tadokoro.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
