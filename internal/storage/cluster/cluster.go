package cluster

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/turnly/oauth-middleware/internal/authentication"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/turnly/oauth-middleware/internal/api/storage/v1alpha1"
	"github.com/turnly/oauth-middleware/internal/storage"
)

var (
	ErrCookieValidation = errors.New("claimsID cookie is invalid")
	ErrSecret           = errors.New("userdata secret error")
)

func CookieValidationError(msg string) error {
	return fmt.Errorf("%w: %s", ErrCookieValidation, msg)
}

func SecretError(msg string) error {
	return fmt.Errorf("%w: %s", ErrSecret, msg)
}

var logger = logrus.New()

type ClusterStorage struct {
	Client     kubernetes.Interface
	Namespace  string
	HmacSecret []byte
	Lifetime   time.Duration
	GCInterval time.Duration

	ticker time.Ticker

	cache         *UserInfoCache
	authenticator *authentication.Authenticator
}

func NewClusterStore(
	client kubernetes.Interface,
	namespace,
	hmacSecret string,
	expiry, cacheTTL time.Duration,
	authenticator *authentication.Authenticator) *ClusterStorage {
	cs := &ClusterStorage{
		Client:        client,
		Namespace:     namespace,
		Lifetime:      expiry,
		HmacSecret:    []byte(hmacSecret),
		cache:         NewUserInfoCache(cacheTTL),
		authenticator: authenticator,
	}
	return cs
}

func (cs *ClusterStorage) Get(r *http.Request) (*v1alpha1.UserInfo, error) {
	claimsId, err := cs.getAndValidateClaimsId(r)
	if err != nil {
		return nil, err
	}

	return cs.cacheGet(claimsId)
}

func (cs *ClusterStorage) Save(r *http.Request, w http.ResponseWriter, info *v1alpha1.UserInfo) error {
	claimsId := cs.generateClaimsID()
	cs.createClaimsIDCookie(claimsId, r, w)
	return cs.storeUserInfo(claimsId, info)
}

func (cs *ClusterStorage) Clear(r *http.Request, w http.ResponseWriter) error {
	claimsId, err := cs.getAndValidateClaimsId(r)
	if err != nil {
		// we can't do anything without the claims id, it's either expired or
		// malformed, do nothing
		return nil
	}
	cs.cache.Delete(claimsId)
	cs.clearClaimsIDCookie(r, w)
	return cs.deleteClaimsSecret(claimsId)
}

func (cs *ClusterStorage) createClaimsIDCookie(claimsId string, r *http.Request, w http.ResponseWriter) {
	cookieData := fmt.Sprintf("%s:%s", claimsId, cs.generateHMAC(claimsId))
	cookie := &http.Cookie{
		Name:     storage.ClaimsIdCookie,
		Value:    cookieData,
		Path:     "/",
		Domain:   cs.authenticator.GetCookieDomain(r),
		Expires:  time.Now().Local().Add(cs.Lifetime),
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}

func (cs *ClusterStorage) clearClaimsIDCookie(r *http.Request, w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     storage.ClaimsIdCookie,
		Value:    "",
		Path:     "/",
		Domain:   cs.authenticator.GetCookieDomain(r),
		Expires:  time.Now().Local().Add(time.Hour * -1),
		Secure:   true,
		HttpOnly: true,
	})
}

func (cs *ClusterStorage) generateClaimsID() string {
	id := make([]byte, storage.ClaimsIdLength)
	_, _ = rand.Read(id)
	return fmt.Sprintf("%x", id)
}

func (cs *ClusterStorage) generateHMAC(claimsId string) string {
	h := hmac.New(sha256.New, cs.HmacSecret)
	h.Write([]byte(claimsId))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (cs *ClusterStorage) checkHMAC(claimsId string, mac string) bool {
	return hmac.Equal([]byte(mac), []byte(cs.generateHMAC(claimsId)))
}

func (cs *ClusterStorage) getAndValidateClaimsId(r *http.Request) (string, error) {
	c, err := r.Cookie(storage.ClaimsIdCookie)
	if err != nil {
		return "", err
	}
	sp := strings.Split(c.Value, ":")
	if len(sp) != 2 {
		return "", CookieValidationError("cookie is malformed")
	}
	claimsId := sp[0]
	mac := sp[1]

	if !cs.checkHMAC(claimsId, mac) {
		return "", CookieValidationError("cookie failed authentication")
	}

	return claimsId, nil
}

func (cs *ClusterStorage) getUserInfoFromSecret(s *corev1.Secret) (*v1alpha1.UserInfo, error) {
	data, ok := s.Data[storage.UserInfoKey]
	if !ok {
		return nil, SecretError("userinfo data missing from secret")
	}

	userinfo := &v1alpha1.UserInfo{}
	if err := json.Unmarshal(data, userinfo); err != nil {
		return nil, fmt.Errorf("%v: %w", SecretError("error parsing userinfo"), err)
	}

	return userinfo, nil
}

func (cs *ClusterStorage) storeUserInfo(claimId string, info *v1alpha1.UserInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("error mashelling userinfo: %w", err)
	}
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: storage.SecretNameBase,
			Labels: map[string]string{
				storage.ClaimsLabel:   "true",
				storage.ClaimsIDLabel: claimId,
			},
		},
		Data: map[string][]byte{
			storage.UserInfoKey: data,
		},
	}

	if _, err := cs.Client.CoreV1().Secrets(cs.Namespace).Create(s); err != nil {
		return fmt.Errorf("%v: %w", SecretError("error creating secret"), err)
	}
	return nil
}

func (cs *ClusterStorage) getSecrets() (*corev1.SecretList, error) {
	return cs.Client.CoreV1().Secrets(cs.Namespace).List(metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", storage.ClaimsLabel),
	})
}

func (cs *ClusterStorage) getSecretByClaim(claimsId string) (*corev1.Secret, error) {
	secrets, err := cs.getSecrets()
	if err != nil {
		return nil, fmt.Errorf("error getting secret list: %w", err)
	}

	for _, s := range secrets.Items {
		cid, ok := s.ObjectMeta.Labels[storage.ClaimsIDLabel]
		if !ok {
			logger.Errorf(
				fmt.Sprintf("found managed secret not containing claimID: offender: %s/%s", s.Namespace, s.Name))
			continue
		}
		if claimsId == cid {
			return &s, nil
		}
	}
	return nil, SecretError("not found:")
}

func (cs *ClusterStorage) deleteClaimsSecret(claimsId string) error {
	secret, err := cs.getSecretByClaim(claimsId)
	if err != nil {
		return err
	}

	if err := cs.Client.CoreV1().Secrets(secret.Namespace).Delete(
		secret.Name, &metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("error deleting secret: %w", err)
	}
	return nil
}

func (cs *ClusterStorage) deleteExpiredSecrets() error {
	secrets, err := cs.getSecrets()
	if err != nil {
		return fmt.Errorf("error getting secret list: %w", err)
	}

	for _, secret := range secrets.Items {
		now := time.Now().UTC()
		if now.Sub(secret.CreationTimestamp.UTC().Add(cs.Lifetime)) >= 0 {
			claimId, ok := secret.Labels[storage.ClaimsIDLabel]
			if ok {
				cs.cache.Delete(claimId)
			}
			if secret.DeletionTimestamp != nil {
				logger.Infof("secret %s already scheduled for deletion", secret.Name)
				continue
			}

			if err := cs.Client.CoreV1().Secrets(cs.Namespace).Delete(
				secret.Name, &metav1.DeleteOptions{}); err != nil {
				logger.Errorf("error deleting expired secret %s/%s: %s", cs.Namespace, secret.Name, err)
			}
		}
	}
	return nil
}

func (cs *ClusterStorage) cacheGet(claimsId string) (*v1alpha1.UserInfo, error) {
	userInfo := cs.cache.Get(claimsId)
	if userInfo != nil {
		return userInfo, nil
	}

	secret, err := cs.getSecretByClaim(claimsId)
	if err != nil {
		return nil, err
	}

	userInfo, err = cs.getUserInfoFromSecret(secret)
	if err != nil {
		return nil, err
	}

	cs.cache.Save(claimsId, userInfo)
	return userInfo, nil
}

func (cs *ClusterStorage) cacheSave(claimsId string, userInfo *v1alpha1.UserInfo) error {
	if err := cs.storeUserInfo(claimsId, userInfo); err != nil {
		return err
	}
	cs.cache.Save(claimsId, userInfo)
	return nil
}
