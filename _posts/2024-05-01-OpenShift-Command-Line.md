# OpenShift Main Commands


## Introdcution

This document is a long list of OpenShift commands grouped togather into chapters. 
I got this list of commands very useful when I started some years ago with OpenShift. 
I didn't put a lot of comments but some of these commands are self explanatory. 


## Troubleshooting



Links:

#### nodes > working-with-nodes  

```
https://access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html/nodes/working-with-nodes
```

#### nodes > working-with-pods

```http
https://access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html/nodes/working-with-pods
```





```
oc get nodes

NAME                    STATUS   ROLES           AGE    VERSION
rhcert5.nca.ihost.com   Ready    master,worker   129d   v1.14.6-152-g117ba1f
oc adm top nodes

NAME                    CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%   
rhcert5.nca.ihost.com   1556m        10%    8247Mi          26%   
oc describe node mynode

Name:               rhcert5.nca.ihost.com
Roles:              master,worker
Labels:             beta.kubernetes.io/arch=amd64
                    beta.kubernetes.io/os=linux
                    kubernetes.io/arch=amd64
                    kubernetes.io/hostname=rhcert5.nca.ihost.com
                    kubernetes.io/os=linux
                    node-role.kubernetes.io/master=
                    node-role.kubernetes.io/worker=
                    node.openshift.io/os_id=rhcos
                    tier=silver
Annotations:        machineconfiguration.openshift.io/currentConfig: rendered-master-6979578433f9fcbdf38a9d260678ea01
                    machineconfiguration.openshift.io/desiredConfig: rendered-master-6979578433f9fcbdf38a9d260678ea01
                    machineconfiguration.openshift.io/reason: 
                    machineconfiguration.openshift.io/state: Done
                    volumes.kubernetes.io/controller-managed-attach-detach: true
CreationTimestamp:  Mon, 08 Feb 2021 15:04:23 +0100
Taints:             <none>
Unschedulable:      false
Lease:
  HolderIdentity:  rhcert5.nca.ihost.com
  AcquireTime:     <unset>
  RenewTime:       Fri, 18 Jun 2021 09:31:45 +0200

Allocated resources:
  (Total limits may be over 100 percent, i.e., overcommitted.)
  Resource           Requests      Limits
  --------           --------      ------
  cpu                4160m (26%)   1280m (8%)
  memory             9834Mi (31%)  787Mi (2%)
  ephemeral-storage  0 (0%)        0 (0%)
  hugepages-2Mi      0 (0%)        0 (0%)
Events:              <none>
export kubeconfig=mypath
```



```
oc login url -u kubeadmin -p password
oc login -u admin -p password
```



```
oc get clusterversion

NAME      VERSION   AVAILABLE   PROGRESSING   SINCE   STATUS
version   4.2.36    True        False         129d    Cluster version is 4.2.36
```



```
oc describe clusterversion

Name:         version
Namespace:    
Labels:       <none>
Annotations:  <none>
API Version:  config.openshift.io/v1
Kind:         ClusterVersion
Metadata:
  Creation Timestamp:  2021-02-08T14:04:10Z
  Generation:          2
  Resource Version:    42590025
  Self Link:           /apis/config.openshift.io/v1/clusterversions/version
  UID:                 841e3378-6a16-11eb-898f-005056b57e23
Spec:
  Channel:     stable-4.2
  Cluster ID:  3fb0dac2-de58-46bd-ac81-f829c6c5fecb
  Overrides:
    Group:      apps/v1
    Kind:       Deployment
    Name:       etcd-quorum-guard
    Namespace:  openshift-machine-config-operator
    Unmanaged:  true
  Upstream:     https://api.openshift.com/api/upgrades_info/v1/graph
```



```
oc get clusteroperators

NAME                                       VERSION   AVAILABLE   PROGRESSING   DEGRADED   SINCE
authentication                             4.2.36    True        False         False      129d
cloud-credential                           4.2.36    True        False         False      129d
cluster-autoscaler                         4.2.36    True        False         False      129d
console                                    4.2.36    True        False         False      129d
dns                                        4.2.36    True        False         False      76d
image-registry                             4.2.36    True        False         False      129d
ingress                                    4.2.36    True        False         False      129d
insights                                   4.2.36    True        False         False      129d
kube-apiserver                             4.2.36    True        False         False      129d
kube-controller-manager                    4.2.36    True        False         False      129d
kube-scheduler                             4.2.36    True        False         False      129d
machine-api                                4.2.36    True        False         False      129d
machine-config                             4.2.36    True        False         False      129d
marketplace                                4.2.36    True        False         False      129d
monitoring                                 4.2.36    True        False         False      4d4h
network                                    4.2.36    True        False         False      129d
node-tuning                                4.2.36    True        False         False      5d5h
openshift-apiserver                        4.2.36    True        False         False      4d4h
openshift-controller-manager               4.2.36    True        False         False      9d
openshift-samples                          4.2.36    True        False         False      129d
operator-lifecycle-manager                 4.2.36    True        False         False      129d
operator-lifecycle-manager-catalog         4.2.36    True        False         False      129d
operator-lifecycle-manager-packageserver   4.2.36    True        False         False      7d10h
service-ca                                 4.2.36    True        False         False      129d
service-catalog-apiserver                  4.2.36    True        False         False      129d
service-catalog-controller-manager         4.2.36    True        False         False      129d
storage                                    4.2.36    True        False         False      129d

```



```
oc adm node-logs -u crio mynode

Data from the specified boot (-1) is not available: No such boot ID in journal
-- Logs begin at Wed 2021-06-16 02:55:46 UTC, end at Fri 2021-06-18 07:40:12 UTC. --
Jun 16 07:08:53 rhcert5.nca.ihost.com crio[2950]: 2021-06-16T07:08:53Z [error] no netns: failed to Statfs "/proc/2327812/ns/net": no such file or directory
Jun 16 07:08:53 rhcert5.nca.ihost.com crio[2950]: 2021-06-16T07:08:53Z [error] cannot set "openshift-sdn" ifname to "eth0": no netns: failed to Statfs "/proc/2327812/ns/net": no such file or directory
Jun 16 07:08:53 rhcert5.nca.ihost.com crio[2950]: 2021-06-16T07:08:53Z [verbose] Del: openshift-marketplace:redhat-operators-8f8dd5db6-g87dh:openshift-sdn:eth0 {"cniVersion":"0.3.1","name":"openshift-sdn","type":"openshift-sdn"}
```



```
oc adm node-logs -u kubelet mynode

Jun 16 05:35:11 rhcert5.nca.ihost.com hyperkube[3036]: I0616 05:35:11.403249    3036 kubelet_pods.go:1346] Generating status for "network-operator-7fd8bbd68c-pbn9s_openshift-network-operator(9171e09e-6a16-11eb-898f-005056b57e23)"
Jun 16 05:35:11 rhcert5.nca.ihost.com hyperkube[3036]: I0616 05:35:11.403568    3036 status_manager.go:382] Ignoring same status for pod "insights-operator-5f69749bfc-txfgr_openshift-insights(943a7270-6a16-11eb-898f-005056b57e23)", status: {Phase:Running Conditions:[{Type:Initialized Status:True LastProbeTime:0001-01-01 00:00:00 +0000 UTC LastTransitionTime:2021-02-08 14:06:04 +0000 UTC Reason: Message:} {Type:Ready Status:True LastProbeTime:0001-01-01 00:00:00 +0000 UTC LastTransitionTime:2021-02-08 14:06:28 +0000 UTC Reason: Message:} {Type:ContainersReady Status:True LastProbeTime:0001-01-01 00:00:00 +0000 UTC LastTransitionTime:2021-02-08 14:06:28 +0000 UTC Reason: Message:} {Type:PodScheduled Status:True LastProbeTime:0001-01-01 00:00:00 +0000 UTC LastTransitionTime:2021-02-08 14:06:03 +0000 UTC Reason: Message:}] Message: Reason: NominatedNodeName: HostIP:192.168.63.155 PodIP:10.128.0.6 StartTime:2021-02-08 14:06:04 +0000 UTC InitContainerStatuses:[] ContainerStatuses:[{Name:operator State:{Waiting:nil Running:&ContainerStateRunning{StartedAt:2021-02-08 14:06:28 +0000 UTC,} Terminated:nil} LastTerminationState:{Waiting:nil Running:nil Terminated:nil} Ready:true RestartCount:0 Image:quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:433c5549a50eea48629df55db5c5072621e8aaeb079f5122f1b3e075c83580cc ImageID:quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:433c5549a50eea48629df55db5c5072621e8aaeb079f5122f1b3e075c83580cc ContainerID:cri-o://6ae95505455827a1331819cda6d7e7ffcd751f5a3d7f8e6d6b174aff00809b18}] QOSClass:Burstable}
```



```
oc debug node/mynode

Starting pod/rhcert5ncaihostcom-debug ...
To use host binaries, run `chroot /host`
chroot host
Pod IP: 192.168.63.155
If you don't see a command prompt, try pressing enter.
sh-4.4# chroot host
sh-4.4# 
sh-4.4# 
sh-4.4# systemctl is-active kubelet
active
sh-4.4# crictl ps
CONTAINER ID        IMAGE                                                                                                                    CREATED             STATE               NAME                                      ATTEMPT             POD ID
34c43bc7263a5       registry.redhat.io/rhel8/support-tools@sha256:d8bf8afb4a8b8293134f63a8254b1a5236489d70ccf2c63c350186a23e439180           30 seconds ago      Running             container-00                              0                   5898eb2c04383
c65f9b33cb0ea       245559d091f4f789e173a0866022df0c22e47d413d6ef3ad3892fa2007213e82                                                         4 hours ago         Running             certified-operators                       0                   a1f8d9f382ea4
6d63b00934404       4d05c0b0932ebfddb2bd358e0b3fb708ba4d53d72adf9556f26d566ba4ad6423             


```



```
oc logs mypod -c mycontainer

---> Running application from Python script (app.py) ...
 * Serving Flask app "app" (lazy loading)
 * Environment: production
   WARNING: Do not use the development server in a production environment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on http://0.0.0.0:8080/ (Press CTRL+C to quit)
```



```
oc debug deploy/mydeploy --as-root

Starting pod/loadtest-debug ...
Pod IP: 10.128.0.25
If you don't see a command prompt, try pressing enter.
(app-root)sh-4.2$ 
(app-root)sh-4.2$ 
(app-root)sh-4.2$ ps
    PID TTY          TIME CMD
      1 pts/0    00:00:00 sh
     24 pts/0    00:00:00 ps
```



```
oc rsh mypod

(app-root)sh-4.2$ ps -efa
UID          PID    PPID  C STIME TTY          TIME CMD
1000620+       1       0  0 Jun17 ?        00:00:21 python app.py
1000620+      34       0  0 07:55 pts/0    00:00:00 /bin/sh
1000620+      59      34  0 07:55 pts/0    00:00:00 ps -efa
```



```
oc cp myfile mypod:mypath

```



```
oc port-forward mypod localport:remoteport

```



```
oc get pods --log-level 6

```



```
oc whoami
oc whoami -t

```



```
oc adm top  nodes -l node-role.kubernetes.io/master= 

NAME                    CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%   
rhcert5.nca.ihost.com   1416m        9%     8301Mi          26%  
```



```
oc logs --tail 5 -n myspace mypod -c mycontainer

 * Environment: production
   WARNING: Do not use the development server in a production environment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on http://0.0.0.0:8080/ (Press CTRL+C to quit)

```



```
oc debug node/mynode
systemctl status kubelet
systemctl status cri-o
crictl ps --name openvswitch
```



```
oc new-project myproject
oc project myproject
oc status
```



```
oc get events

LAST SEEN   TYPE      REASON                         OBJECT                             MESSAGE
25m         Normal    Scheduled                      pod/loadtest-debug                 Successfully assigned schedule-review/loadtest-debug to rhcert5.nca.ihost.com
25m         Normal    Pulled                         pod/loadtest-debug                 Container image "quay.io/redhattraining/loadtest:v1.0" already present on machine
25m         Normal    Created                        pod/loadtest-debug                 Created container loadtest
25m         Normal    Started                        pod/loadtest-debug                 Started container loadtest
24m         Normal    Killing                        pod/loadtest-debug                 Stopping container loadtest

```



Find an image in a registry

```
skopeo inspect docker://registry.access.redhat.com/... 
```



```
yum install nano
export EDITOR=nano
oc edit deploy/mydeploy
```



## Identity Providers



Links:

#### authentication > configuring-identity-providers

```
https://access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html/authentication/configuring-identity-providers
```



Examples: htpasswd, keystone, OpenLDAP, GitHub, activeDirectory ...



Authentication with X509 certificate in a auth directory

```
export KUBECONFIG=/home/user/auth/kubeconfig
oc get nodes
```



Authentication with a virtual user

```
oc login -u kubeadmin -p shdU_trbi_6ucX_edbu_aqop
oc delete secret kubeadmin -n kube-system
```



Get the OAuth custom resource

```
oc get -o yaml oauth cluster > oauth.yaml

apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  annotations:
    release.openshift.io/create-only: "true"
  creationTimestamp: "2021-02-08T14:05:03Z"
  generation: 2
  name: cluster
  resourceVersion: "40404270"
  selfLink: /apis/config.openshift.io/v1/oauths/cluster
  uid: a3d27f98-6a16-11eb-898f-005056b57e23
spec:
  identityProviders:
  - htpasswd:
      fileData:
        name: htp-secret
    mappingMethod: claim
    name: myusers
    type: HTPasswd

```



Locally define/modify/delete htpasswd file

```
yum install htpasswd -y
htpasswd -c -B -b htpasswd newuser redhat123
htpasswd -b htpasswd existinguser redhat1234
htpasswd -D htpasswd existinguser
```



Define the htpasswd secret

```
oc create secret generic htp-secret --from-file htpasswd=/home/user/htpasswd -n openshift-config
```



Listing the secret:

```
oc extract secret/htp-secret -n openshift-config --to - > temp
cat temp
htpasswd -D temp manager
oc delete user manager
oc delete identity manager
```



After Changing the htpasswd file, you must update the secret

```
oc create secret generic htp-secret --from-file htpasswd=/path/to/your/file --dry-run -o yaml | oc replace -n openshift-config -f -
```



Associate cluster admin privileges to a new user:

```
oc adm policy add-cluster-role-to-user cluster-admin newuser
```



Listing users, identities, ...

```
oc get users
oc get identity
oc edit oauth
oc delete user --all
oc delete identity -all
```



## RBAC (Role Based Access Control)



Links

#### authentication > using-rbac

```
https://access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html/authentication/using-rbac
```



Resources (pods, service ...) <--- Role (get, list, delete ...) <--- Binding ---> Entity (user, group sa)

Roles: Cluster roles or Local roles

```
oc adm policy who-can delete user
```



Roles:

- admin
- basic-user
- cluster-admin
- cluster-status
- edit
- self-provisioner 
- view



```
oc get clusterrolebinding -o wide | grep -E 'NAME|self-provisioner'

NAME                                                                              AGE
self-provisioners                                                                 129d
```



```
oc describe clusterrolebindings self-provisioners

Name:         self-provisioners
Labels:       <none>
Annotations:  rbac.authorization.kubernetes.io/autoupdate: true
Role:
  Kind:  ClusterRole
  Name:  self-provisioner
Subjects:
  Kind   Name                        Namespace
  ----   ----                        ---------
  Group  system:authenticated:oauth  
```



Remove self-provisioner cluster role from group **system:authenticated:oauth**

```
oc adm policy remove-cluster-role-from-group self-provisioner system:authenticated:oauth
```



```
oc policy add-role-to-user admin myuser
```



```
oc adm groups new mygroup
```



```
oc admn groups add-users mygroup myuser
oc get groups
```



```
oc policy add-role-to-group edit mygroup
oc policy add-role-to-group view mygroup
```



```
oc new-app --name httpd httpd:2.4
```





## Secrets



Links

#### Node > nodes-pods-secrets

```
https://access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html/nodes/working-with-pods#nodes-pods-secrets-about_nodes-pods-secrets
```





Create a secret from literals

```
oc create secret generic secret_name --from-literal key1=secret1 --from-literal key2=secret2
```

Create secret from file to sa

```
oc secrets add --for mount serviceaccount/serviceaccount-name secret/secret_name
```



Expose a secret in a POD

```
env:
  - name: MYSQL_ROOT_PASSWORD
    valueFrom:
      secretKeyRef:
        name: demo-secret 
        key: root_password
```

or with oc command

```
oc set env dc/demo --from=secret/demo-secret --prefix MYPREF
```



Create a new-app **deploymentConfig**

```
oc new-app --name myapp --docker-image registry.access.redhat.com/rhscl/mysql-57-rhel7:5.7-47
```



List all pods for a label with the **watch** option:

```
oc get pods -l app=myapp -w
```





## Security Context Constaints



Links

#### Authentication > Managing-pod-security-policies

```
https://access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html-single/authentication/index#managing-pod-security-policies
```





List all SCC

```
oc get scc

NAME               AGE
anyuid             129d
hostaccess         129d
hostmount-anyuid   129d
hostnetwork        129d
node-exporter      129d
nonroot            129d
privileged         129d
restricted         129d
```



Describe a specific SCC

```
oc describe scc anyuid

Name:                       anyuid
Priority:                   10
Access:                     
  Users:                    <none>
  Groups:                   system:cluster-admins
Settings:                   
  Allow Privileged:             false
  Allow Privilege Escalation:           true
  Default Add Capabilities:         <none>
  Required Drop Capabilities:           MKNOD
  Allowed Capabilities:             <none>
  Allowed Seccomp Profiles:         <none>
  Allowed Volume Types:             configMap,downwardAPI,emptyDir,persistentVolumeClaim,projected,secret
  Allowed Flexvolumes:              <all>
  Allowed Unsafe Sysctls:           <none>
  Forbidden Sysctls:                <none>
  Allow Host Network:               false
  Allow Host Ports:             false
  Allow Host PID:               false
  Allow Host IPC:               false
  Read Only Root Filesystem:            false
  Run As User Strategy: RunAsAny        
    UID:                    <none>
    UID Range Min:              <none>
    UID Range Max:              <none>
  SELinux Context Strategy: MustRunAs       
    User:                   <none>
    Role:                   <none>
    Type:                   <none>
    Level:                  <none>
  FSGroup Strategy: RunAsAny            
    Ranges:                 <none>
  Supplemental Groups Strategy: RunAsAny    
    Ranges:                 <none>
```



Create a Sarvice Account (sa)

```
oc create sa saname
```



Associate a SCC to a SA:

```
oc adm policy add-scc-to-user myscc -z saname
```



Assign SA to a POD

```bash
oc set serviceaccount deploymentconfig mydc saname
oc set sa deploy mydeploy saname
```





Look at the SCC associated to a pod

```
oc get pod podname -o yaml | oc adm policy scc-subject-review -f -
```





## Services



Links

#### Networking > Configuring Networking Policy

```
https://access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html-single/networking/index#configuring-networkpolicy
```





```
oc get svc

NAME       TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)   AGE
loadtest   ClusterIP   172.30.148.181   <none>        80/TCP    28h
```



DNS Operator

```
oc describe dns.operator/default
```



Cluster Network Operator

```
oc get Network.config.openshift.io cluster -o yaml

apiVersion: config.openshift.io/v1
kind: Network
metadata:
  creationTimestamp: "2021-02-08T14:04:09Z"
  generation: 2
  name: cluster
  resourceVersion: "1449"
  selfLink: /apis/config.openshift.io/v1/networks/cluster
  uid: 8385395b-6a16-11eb-898f-005056b57e23
spec:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  externalIP:
    policy: {}
  networkType: OpenShiftSDN
  serviceNetwork:
  - 172.30.0.0/16
status:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  clusterNetworkMTU: 1450
  networkType: OpenShiftSDN
  serviceNetwork:
  - 172.30.0.0/16

```



Retreive IP addresses:

```
oc get service/frontend -o jsonpath="{.spec.clusterIP}{'\n'}"
```



Debuging

```
oc debug -t deployment/mysql --image registry.access.redhat.com/ubi8/ubi:8.0
```





# Routes

Links

####Networking > Configuring Routes

```bash 
https://access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html-single/networking/index#configuring-routes
```



HTTP, HTTPS, SNI, TLSwith SNI

Secure Routes : 

- edge
- pass-through
- re-encryption



Insecure Routes

```
oc expose service api-frontend --hostname api.apps.acme.com

oc create secret tls todo-certs --cert=certs/training.crt --key=certs/training.key
```



Securing Applications at the edge

```
oc create route edge myroute --service myservice --hostname --api.apps.acme.com --key api.key --cert api.crt

oc create route passthrough todo-https --service todo-https --port 8443 --hostname todo-https.domain.com
```



Anaysing the network trafic

```
ip a | grep 172.25.250.9

sudo tcpdump -i ens3 -A -n port 80 | grep js

oc extract secrets/router-ca --keys tls.crt -n openshift-ingress-operator

curl -I -v --cacert tls.crt https://todo-https.com
```



Etapes pour la gestion des certificats:

```
openssl genrsa -out training.key 2048

openssl req -new -subj "/C=US/ST=North Carolina/L=Raleigh/O=Red Hat/CN=todo https.com" -key training.key -out training.csr

openssl x509 -req -in training.csr -passin file:passphrase.txt -CA training-CA.pem -CAkey training-CA.key -CAcreateserial -out training.crt -days 1825 -sha256 -extfile training.ext

curl -vvI --cacert certs/training-CA.pem https://todo-https.${RHT_OCP4_WILDCARD_DOMAIN}
```





## POD SCheduling



Links

#### Nodes > Placement

```
https://access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html-single/nodes/index#nodes-pods-node-selectors
```







```
oc get node mypod --show-labels

NAME                    STATUS   ROLES           AGE    VERSION                LABELS
rhcert5.nca.ihost.com   Ready    master,worker   129d   v1.14.6-152-g117ba1f   beta.kubernetes.io/arch=amd64,beta.kubernetes.io/os=linux,kubernetes.io/arch=amd64,kubernetes.io/hostname=rhcert5.nca.ihost.com,kubernetes.io/os=linux,node-role.kubernetes.io/master=,node-role.kubernetes.io/worker=,node.openshift.io/os_id=rhcos,tier=silver
```



```
oc get node -l env=prod
```



Labelling nodes

```
oc label node mynode env=dev --overwrite
oc label node mynode env-
```



Node List

```
oc get node mynode --show-labels
oc get node -L failure-domain.beta.kubernetes.io/region
```



Controlling POD placement with Node Selector

```
  template:
    metadata:
      creationTimestamp: null
      labels:
        app: myapp
    spec:
      nodeSelector:
        env: dev
      containers:
      - image: quay.io/redhattraining/scaling:v1.0
```



Configuring a Node Selector for a Project creation

```
oc adm new-project demo --node-selector "tier=1"
```

or after project creation

```
oc annotate namespace demo openshift.io/node-selector="tier=2" --overwrite
```





## Resource Usage and limits

Links

#### Applications > Limits

Requests = minimum resources (cpu or memory) to run a POD on a node

Limits = maximum limit to run a pod in a node

```
    spec:
      containers:
      - image: quay.io/redhattraining/hello-world-nginx:v1.0
          name: hello-world-nginx
          resources:
            requests:
              cpu: "10m"
              memory: 20Mi
            limits:
              cpu: "80m"
              memory: 100Mi
```

or

```
oc set resources deploy mydeploy --requests cpu=10m,memory=20Mi --limits cpu=80m,memory=100Mi
```



Resource list for a node

```
oc describe node mynode
```



Statistics for all nodes

```
oc adm top nodes -l myworkernode
oc adm top pods
```





## Quotas

Links

#### Applications > Quotas

```
https://access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html-single/applications/index#quotas
```



| Resource                 | Quota                                    |
| ------------------------ | ---------------------------------------- |
| pods                     | Total number of pods                     |
| `replicationcontrollers` | Total number of replication controllers  |
| services                 | Total number of services                 |
| secrets                  | Total number of secrets                  |
| `persistentvolumeclaims` | Total number of persistent volume claims |

| Resource                   | Quota                                                        |
| -------------------------- | ------------------------------------------------------------ |
| cpu (requests.cpu)         | Total CPU use across all containers                          |
| memory (requests.memory)   | Total memory use across all containers                       |
| storage (requests.storage) | Total storage requests by containers across all persistent volume claims |



**Resource Quota for the scope for a project**

```
oc create quota dev-quota --hard services=10,cpu=1300,memory=1.5Gi
oc describe quota dev-quota
oc delete resourcequota QUOTA
```



**Cluster Quota** for all projects owned by myuser

```
oc create clusterquota user-qa --project-annotation-selector openshift.io/requester=myuser --hard pods=12,secrets=20
```



**Cluster Quota for all projects** for a specific label (environment=qa)

```
oc create clusterquota env-qa --project-label-selector environment=qa --hard pods=10,services=5
```



Delete a cluster quota

```
oc delete clusterquota QUOTA
```





## Limit Ranges

Limits for a single container or a pod

To understand the difference between a limit range and a resource quota, consider that a limit range defines valid ranges and default values for a single pod, and a resource quota defines only top values for the sum of all pods in a project. A cluster administrator concerned about resource usage in an OpenShift cluster usually defines both limits and quotas for a project.

Limite Range for a container or a pod, an image, or a PVC.

| Type      | Resource Name                                                | Description                                                  |
| --------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Container | cpu                                                          | Minimum and maximum CPU allowed and default CPU set per container |
| memory    | Minimum and maximum memory allowed and default memory set per container |                                                              |
| Pod       | cpu                                                          | Minimum and maximum CPU allowed across all containers in a pod |
| memory    | Minimum and maximum memory allowed across all containers in a pod |                                                              |
| Image     | storage                                                      | Maximum size of an image that can be pushed to the internal registry |
| PVC       | storage                                                      | Minimum and maximum capacity of the volume that can be requested by one claim |





## Scaling the Application

Links

#### Applications > Autoscale



Deployment > Replicas > template > Containers 			`oc create deploy`

DeploymentConfig > Replicas > Template > Selector 		`oc new-app`



Manual

```
oc scale --replicas 3 deploy/myname
oc scale --replicas 3 dc/myname
```



Automatic 

```
oc autoscale dc/myname --min 1 --max 10 --cpu-percent 80
oc autoscale deploy/myname --min 1 --max 10 --cpu-percent 80
```

List all autoscalers

```
oc get hpa
oc delete hpa myname
```

 




