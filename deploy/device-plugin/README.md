# NVIDIA device plugin (k8s-worker)

`nvidia-device-plugin.yaml` — NVIDIA k8s-device-plugin **v0.20.1** as a DaemonSet in CDI mode
(`DEVICE_LIST_STRATEGY=cdi-cri`). The node runs plain runc under containerd 2.x with CDI enabled; there is no
NVIDIA container runtime. The plugin reads the host driver through a read-only mount of `/` at `/driver-root`,
writes its CDI specification into `/var/run/cdi` and advertises `nvidia.com/gpu`; pods request
`resources.limits: {nvidia.com/gpu: 1}`.

Deploy (placeholders for namespace and the node selector/taint of the target nodes):
```
sed -e 's/NAMESPACE/<ns>/' -e 's/NODE_SELECTOR_KEY: NODE_SELECTOR_VALUE/<key>: <value>/' \
    -e 's/TOLERATION_KEY/<taint key>/' -e 's/TOLERATION_VALUE/<taint value>/' nvidia-device-plugin.yaml | kubectl apply -f -
```
Only the device plugin; GPU Operator, NFD and HAMi are not part of this profile.
