module github.com/mesosphere/traefik-forward-auth

go 1.12

require (
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/cenkalti/backoff v2.1.1+incompatible // indirect
	github.com/containous/alice v0.0.0-20181107144136-d83ebdd94cbd // indirect
	github.com/containous/flaeg v1.4.1 // indirect
	github.com/containous/mux v0.0.0-20181024131434-c33f32e26898 // indirect
	github.com/containous/traefik v2.0.0-alpha2+incompatible
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/go-acme/lego v2.5.0+incompatible // indirect
	github.com/go-kit/kit v0.8.0 // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/gorilla/context v1.1.1 // indirect
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/sessions v1.2.0
	github.com/gravitational/trace v0.0.0-20190409171327-f30095ced5ff // indirect
	github.com/jonboulle/clockwork v0.1.0 // indirect
	github.com/json-iterator/go v1.1.8 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/miekg/dns v1.1.8 // indirect
	github.com/onsi/ginkgo v1.10.1 // indirect
	github.com/onsi/gomega v1.7.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	github.com/thomseddon/go-flags v1.4.1-0.20190507184247-a3629c504486
	github.com/vulcand/predicate v1.1.0 // indirect
	golang.org/x/crypto v0.0.0-20190820162420-60c769a6c586 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e // indirect
	golang.org/x/sys v0.0.0-20190826190057-c7b8b68b1456 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	gopkg.in/square/go-jose.v2 v2.3.1 // indirect
	gopkg.in/yaml.v2 v2.2.8
	gotest.tools v2.2.0+incompatible
	k8s.io/api v0.17.0
	k8s.io/apimachinery v0.17.0
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/kube-openapi v0.0.0-20191107075043-30be4d16710a // indirect
	k8s.io/utils v0.0.0-20200109141947-94aeca20bf09 // indirect
)

replace (
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
)
