{{- define "cfssl.labels" -}}
generator: "helm"
updated: {{ now | htmlDate | quote }}
chart: {{ .Chart.Name | quote }}
chart_version: {{ .Chart.Version | quote }}
release: {{ .Release.Name | quote }}
release_version: "{{ .Chart.Version }}_{{ .Release.Time.Seconds }}"
ci_user: {{ .Values.ciUser | quote }}
ci_build_number: {{ .Values.ciBuildNumber | quote }}
ci_branch: {{ .Values.ciBranch | quote }}
ci_dep_user: {{ .Values.ciDeployUser | quote }}
ci_dep_build_number: {{ .Values.ciDeployBuildNumber | quote }}
{{- end -}}

{{- define "cfssl.labels-selector" -}}
chart: {{ .Chart.Name | quote }}
{{- end -}}

{{- define "cfssl.envs" -}}
# if the variable is changed in runtime, pods will be updated
# Check this: https://github.com/kubernetes/kubernetes/issues/13488#issuecomment-240393845
- name: DUMMY_VARIABLE_FOR_RESTART
  value: {{ .Values.ciDummyRestart | quote }}
- name: AUTH_KEY
  valueFrom:
    secretKeyRef:
      key: secret-key
      name: cfssl-auth
- name: CA-CERT
  valueFrom:
    secretKeyRef:
      key: ca-cert
      name: cfssl-config
- name: CA-KEY
  valueFrom:
    secretKeyRef:
      key: ca-key
      name: cfssl-config
- name: CA-CONFIG
  valueFrom:
    secretKeyRef:
      key: ca-config
      name: cfssl-config
{{- end -}}
