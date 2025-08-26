# Issues on Probes of Kubernetes and Istio Since 2020

66 issues related to liveness and readiness probes in two open-source
projects, Kubernetes and Istio, ranging from 2020
to March 2024.

The study is about **"What issues on probes occur in practice?"**

### A. Program Implementations
#### A1. Implementation Bugs and Security Problems
**Kubernetes**
1. [readiness liveness probe issue with springboot and kubernetes](https://github.com/kubernetes/kubernetes/issues/91879)
2. [Pod probes lead to blind SSRF from the node](https://github.com/kubernetes/kubernetes/issues/99425)
3. [Pod readiness probe cannot be directed at specific IP family](https://github.com/kubernetes/kubernetes/issues/101324)
4. [ReadinessProbe not working](https://github.com/kubernetes/kubernetes/issues/114250)

**Istio**
1. [probe httpheaders are duplicated when using istio probe rewriting](https://github.com/istio/istio/issues/28466)
2. [Breaking when PODs have HTTP GET readiness and liveness probes and they do not start with a /](https://github.com/istio/istio/issues/27583)
3. [Readiness probe failed for prometheus and pods that dose not have Readiness probe set](https://github.com/istio/istio/issues/26367)
4. [Rewrite app probe sends requests to the wrong endpoint, breaking pod IP listeners](https://github.com/istio/istio/issues/25177)
5. [Probe rewriting fails to handle additional httpHeaders](https://github.com/istio/istio/issues/23482)
6. [rewriteAppHTTPProbe drops startupProbe](https://github.com/istio/istio/issues/24203)
7. [Istio rewrites HTTP probes incorrectly](https://github.com/istio/istio/issues/36684)


### B. Configurations and Probe Compatibility
#### B1. Configuration Failures and Incompatibility
**Kubernetes**
1. [readiness prober timeout do not run as expected](https://github.com/kubernetes/kubernetes/issues/123931)
2. [Liveness probe periodSeconds is not honoured](https://github.com/kubernetes/kubernetes/issues/90108)
3. [readiness and liveness issue deploying it to EKS](https://github.com/kubernetes/kubernetes/issues/91880)
4. [readiness and liveness scope restriction](https://github.com/kubernetes/kubernetes/issues/91916)
5. [startupProbe is not applied to Pod if serviceAccountName is set](https://github.com/kubernetes/kubernetes/issues/95604)
6. [[Probes] Incorrect application of the initialDelaySeconds](https://github.com/kubernetes/kubernetes/issues/96614)
7. [The timeout of exec probe did not take effect as expected](https://github.com/kubernetes/kubernetes/issues/107306)
8. [readiness probe is not scheduled as configured periodSeconds](https://github.com/kubernetes/kubernetes/issues/118815)

**Istio**
1. [istio - rewriteAppHTTPProbers default value true causes connection pooling issues for probe requests](https://github.com/istio/istio/issues/49454)
2. [Probe rewrite broken for custom host](https://github.com/istio/istio/issues/46215)
3. [pod liveness probe fails when service is added to deployment](https://github.com/istio/istio/issues/24941)
4. [Healthchecks are failed because of AuthorizationPolicy](https://github.com/istio/istio/issues/22316)


#### B2. Probe Incompatibility
**Kubernetes**
1. [About Startup Probes - need more information about starting time of startup probes](https://github.com/kubernetes/kubernetes/issues/88956)
2. [Pods which have not "started" can not be "ready"](https://github.com/kubernetes/kubernetes/pull/92196)
3. [Pods with a startup probe but without a readiness probe take a long time to become ready](https://github.com/kubernetes/kubernetes/issues/95436)
4. [startupProbe readiness state update issues](https://github.com/kubernetes/kubernetes/issues/95140)
5. [Allow adding healthz and livez checks independent to each other](https://github.com/kubernetes/kubernetes/pull/99064)
6. [Liveness probes are running before startup probe and causing container to restart](https://github.com/kubernetes/kubernetes/issues/105308)
7. [liveness and readiness probe delays](https://github.com/kubernetes/kubernetes/pull/119666)



**Istio**
1. [Kubernetes httpGet liveness/readiness probes fail if Istio-proxy has to follow redirect](https://github.com/istio/istio/issues/34238)
2. [istio-proxy connection refused for healthchecks](https://github.com/istio/istio/issues/39036)


### C. Runtime Problems
#### C1. Lack of Failure Information
**Kubernetes**
1. [Readiness probe failed: net/http: request canceled (Client.Timeout exceeded while awaiting headers)](https://github.com/kubernetes/kubernetes/issues/88555)
2. [Sometime Liveness/Readiness Probes fail because of net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)](https://github.com/kubernetes/kubernetes/issues/89898)
3. [Liveness probe failed: context deadline exceeded (Client.Timeout exceeded while awaiting headers)](https://github.com/kubernetes/kubernetes/issues/115469)
4. [startup probe restarts without back-off (and looses events)](https://github.com/kubernetes/kubernetes/issues/99697)
5. [Confusing/incomplete readiness probe warning when doing external redirections](https://github.com/kubernetes/kubernetes/issues/103877)
6. [add container probe duration metrics](https://github.com/kubernetes/kubernetes/pull/104484)
7. [Liveness/Readiness probe timed out but no reason found in pod describe events](https://github.com/kubernetes/kubernetes/issues/106111)
8. [Liveness probe failing when the load on the application is maxed](https://github.com/kubernetes/kubernetes/issues/110083)

**Istio**
1. [Cannot see liveness probe and readiness probe logs in envoy proxy logs](https://github.com/istio/istio/issues/49862)
2. [Envoy liveness probe failing due to Client.Timeout exceeded while awaiting headers](https://github.com/istio/istio/issues/32727)
3. [Liveness and Readiness probes failing in kubernetes cluster - istio proxy sidecar injection is enabled in application](https://github.com/istio/istio/issues/32687)
4. [my application pods status not ready correctly](https://github.com/istio/istio/issues/23461)
5. [Liveness Readiness failing in istio with load increase](https://github.com/istio/istio/issues/42542)


#### C2. Delayed or Incorrect Status Probing
**Kubernetes**
1. [[Documentation] Update the TCP probe documentation do explain when the application will really be "not alive"](https://github.com/kubernetes/kubernetes/issues/103632)
2. [When publishNotReadyAddresses is set to true, Services route traffic to not-ready Pods anyway](https://github.com/kubernetes/kubernetes/issues/118952)
3. [daemonset pods not recognising that nodes are not ready, pod stays running](https://github.com/kubernetes/kubernetes/issues/121100)
4. [Liveness/Readiness Health Check sometimes failed](https://github.com/kubernetes/kubernetes/issues/95165)
5. [Stop probing a pod during graceful shutdown](https://github.com/kubernetes/kubernetes/pull/98571)
6. [Liveness Probe with an invalid command doesn't trigger container restarts and ContainersReady remains True](https://github.com/kubernetes/kubernetes/issues/106682)
7. [Pods are in RUNNING state hours after Node is deleted from google cloud](https://github.com/kubernetes/kubernetes/issues/107493)


**Istio**
1. [Health Checks are not appropriate](https://github.com/istio/istio/issues/44963)
2. [Kubernetes httpGet liveness probes fail with IstioProxy returning a HTTP 500](https://github.com/istio/istio/issues/36228)
3. [Pod reports readiness probe failing on container “istio-proxy”](https://github.com/istio/istio/issues/39447)
4. [istio-1.10.4 -- istio-proxy Readiness Probe Failing and making application pod as Unhealthy](https://github.com/istio/istio/issues/37888)


#### C3. Mistaken Operations Unmatching Status
**Kubernetes**
1. [Readiness prob not restarting pod when it getting 503 http status](https://github.com/kubernetes/kubernetes/issues/93994)
2. [kube-proxy: persistent connection kept alive although readiness checks fails (and POD not ready)](https://github.com/kubernetes/kubernetes/issues/100492)
3. [k8s liveness probe fails during pod termination](https://github.com/kubernetes/kubernetes/issues/107473)
4. [Liveness probe with an error doesn't trigger container restart](https://github.com/kubernetes/kubernetes/issues/122591)
5. [kublet prober infinite Readiness check - no Liveness probe defeating self-heal](https://github.com/kubernetes/kubernetes/issues/123778)
6. [Readiness probes are called even when pod is in terminating state](https://github.com/kubernetes/kubernetes/issues/122824)
7. [ReadinessProbe not working](https://github.com/kubernetes/kubernetes/issues/114250)
8. [kubelet: add probe termination to graceful shutdowns](https://github.com/kubernetes/kubernetes/pull/105215)
9. [Readiness probes should keep running (or pod marked as not ready) during graceful node termination](https://github.com/kubernetes/kubernetes/issues/105780)

**Istio**

1. [Do not keep connections alive for intercepted health probes](https://github.com/istio/istio/issues/36390)
