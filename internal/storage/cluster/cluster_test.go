package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mesosphere/traefik-forward-auth/internal/api/storage/v1alpha1"
	"github.com/mesosphere/traefik-forward-auth/internal/authentication"
	"github.com/mesosphere/traefik-forward-auth/internal/configuration"
	"github.com/mesosphere/traefik-forward-auth/internal/storage"
	"gotest.tools/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var hmacSecret = "secret"

func TestClusterStorage_Get(t *testing.T) {
	fakeClaimID := "abcdefg12345"
	fakeUserInfo := &v1alpha1.UserInfo{
		Username: "security@d2iq.com",
		Email:    "security@d2iq.com",
		Groups:   []string{"engineering", "security", "beer"},
	}
	datum, _ := json.Marshal(fakeUserInfo)
	userInfoSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tfa-secret-12345",
			Namespace: "default",
			Labels: map[string]string{
				storage.ClaimsLabel:   "true",
				storage.ClaimsIDLabel: fakeClaimID,
			},
		},
		Data: map[string][]byte{
			storage.UserInfoKey: datum,
		},
	}
	client := fake.NewSimpleClientset(userInfoSecret)
	a := authentication.NewAuthenticator(&configuration.Config{})
	cs := NewClusterStore(client, "default", hmacSecret, time.Hour, time.Minute, a)
	r := http.Request{
		Method: "GET",
		Proto:  "HTTP/1.1",
		Header: map[string][]string{
			"Cookie": {fmt.Sprintf("%s=%s:%s", storage.ClaimsIdCookie, fakeClaimID, cs.generateHMAC(fakeClaimID))},
		},
	}

	userInfo, err := cs.Get(&r)
	if err != nil {
		t.Fatalf("error getting userinfo: %v", err)
	}

	assert.DeepEqual(t, userInfo, fakeUserInfo)

	fmt.Printf("cache: %v\n", cs.cache.infos)

	cached := cs.cache.Get(fakeClaimID)
	assert.DeepEqual(t, cached, fakeUserInfo)
}

func TestClusterStorage_Save(t *testing.T) {
	client := fake.NewSimpleClientset()
	a := authentication.NewAuthenticator(&configuration.Config{})
	cs := NewClusterStore(client, "default", hmacSecret, time.Hour, time.Minute, a)

	r := &http.Request{
		Header: map[string][]string{
			"X-Forwarded-Host": {"localhost"},
		},
	}
	rr := &httptest.ResponseRecorder{}
	fakeUserInfo := &v1alpha1.UserInfo{
		Username: "security@d2iq.com",
		Email:    "security@d2iq.com",
		Groups:   []string{"engineering", "security", "beer"},
	}
	assert.NilError(t, cs.Save(r, rr, fakeUserInfo))

	// Test retrieval

	cookie := rr.Header().Get("Set-Cookie")
	newr := &http.Request{
		Header: map[string][]string{
			"Cookie": {cookie},
		},
	}

	userInfo, err := cs.Get(newr)
	assert.NilError(t, err)
	assert.DeepEqual(t, userInfo, fakeUserInfo)
}

func TestClusterStorage_Clear(t *testing.T) {
	fakeClaimID := "abcdefg12345"
	fakeUserInfo := &v1alpha1.UserInfo{
		Username: "security@d2iq.com",
		Email:    "security@d2iq.com",
		Groups:   []string{"engineering", "security", "beer"},
	}
	datum, _ := json.Marshal(fakeUserInfo)
	userInfoSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tfa-secret-12345",
			Namespace: "default",
			Labels: map[string]string{
				storage.ClaimsLabel:   "true",
				storage.ClaimsIDLabel: fakeClaimID,
			},
		},
		Data: map[string][]byte{
			storage.UserInfoKey: datum,
		},
	}
	client := fake.NewSimpleClientset(userInfoSecret)
	a := authentication.NewAuthenticator(&configuration.Config{})
	cs := NewClusterStore(client, "default", hmacSecret, time.Hour, time.Minute, a)
	r := http.Request{
		Method: "GET",
		Proto:  "HTTP/1.1",
		Header: map[string][]string{
			"Cookie": {fmt.Sprintf("%s=%s:%s", storage.ClaimsIdCookie, fakeClaimID, cs.generateHMAC(fakeClaimID))},
		},
	}
	rr := &httptest.ResponseRecorder{}
	err := cs.Clear(&r, rr)
	assert.NilError(t, err)
	_, err = cs.Client.CoreV1().Secrets(cs.Namespace).Get(context.Background(), "tfa-secret-12345", metav1.GetOptions{})
	assert.ErrorContains(t, err, "not found")
}
