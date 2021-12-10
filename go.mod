module github.com/mesosphere/traefik-forward-auth

go 1.12

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/googleapis/gnostic v0.5.7 // indirect
	github.com/gorilla/sessions v1.2.1
	github.com/gravitational/trace v1.1.15 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/thomseddon/go-flags v1.4.1-0.20190507184247-a3629c504486
	github.com/traefik/traefik/v2 v2.5.4
	golang.org/x/crypto v0.0.0-20211202192323-5770296d904e // indirect
	golang.org/x/net v0.0.0-20211201190559-0a0e4e1bb54c // indirect
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8
	golang.org/x/sys v0.0.0-20211124211545-fe61309f8881 // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20211116232009-f0f3c7e86c11 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/yaml.v2 v2.4.0
	gotest.tools v2.2.0+incompatible
	k8s.io/api v0.22.4
	k8s.io/apimachinery v0.22.4
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65 // indirect
	k8s.io/utils v0.0.0-20211203121628-587287796c64 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

replace (
	github.com/abbot/go-http-auth => github.com/containous/go-http-auth v0.4.1-0.20200324110947-a37a7636d23e
	github.com/go-check/check => github.com/containous/check v0.0.0-20170915194414-ca0bf163426a
	github.com/googleapis/gnostic => github.com/google/gnostic v0.5.5
	github.com/gorilla/mux => github.com/containous/mux v0.0.0-20181024131434-c33f32e26898
	github.com/tencentcloud/tencentcloud-sdk-go => github.com/tencentcloud/tencentcloud-sdk-go v1.0.305
	k8s.io/api => k8s.io/api v0.0.0-20191219150132-17cfeff5d095
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20191219152659-2a2858d6f688
	k8s.io/apimachinery => k8s.io/apimachinery v0.16.5-beta.1.0.20191219145857-f69eda767ee8
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20191219151601-3d31b68088a0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20191219153035-366d582810d5
	k8s.io/client-go => k8s.io/client-go v0.0.0-20191016111102-bec269661e48
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.0.0-20191219154137-ba8722d6c806
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.0.0-20191219154003-dff0d89ae048
	k8s.io/code-generator => k8s.io/code-generator v0.16.5-beta.1.0.20191219145618-f86ae06843c6
	k8s.io/component-base => k8s.io/component-base v0.0.0-20191219151120-31489c1247bd
	k8s.io/cri-api => k8s.io/cri-api v0.16.5-beta.1.0.20191219154810-955518131889
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.0.0-20191219154314-0bd97e2070e7
	k8s.io/gengo => k8s.io/gengo v0.0.0-20190822140433-26a664648505
	k8s.io/heapster => k8s.io/heapster v1.2.0-beta.1
	k8s.io/klog => k8s.io/klog v0.4.0
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.0.0-20191219151832-6fd8eae1e3ac
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.0.0-20191219153829-60849847d83d
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20190816220812-743ec37842bf
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.0.0-20191219153344-6256a4ff54db
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.0.0-20191219153653-9473e9ae815c
	k8s.io/kubectl => k8s.io/kubectl v0.0.0-20191219155003-4676d6576eb4
	k8s.io/kubelet => k8s.io/kubelet v0.0.0-20191219153519-5db5b9063a9a
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.0.0-20200107195218-61af050a79f8
	k8s.io/metrics => k8s.io/metrics v0.0.0-20191219152853-c51f23a4a6da
	k8s.io/node-api => k8s.io/node-api v0.0.0-20191219154642-078be89b0ba2
	k8s.io/repo-infra => k8s.io/repo-infra v0.0.0-20181204233714-00fe14e3d1a3
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.0.0-20191219152045-0a9fe71499ff
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.0.0-20191219153213-e3fa3a911b4b
	k8s.io/sample-controller => k8s.io/sample-controller v0.0.0-20191219152357-6e4eb60e6d9a
	k8s.io/utils => k8s.io/utils v0.0.0-20190801114015-581e00157fb1
	launchpad.net/gocheck => gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
)
