package cluster

import (
	"sync"
	"time"

	"github.com/turnly/oauth-middleware/internal/api/storage/v1alpha1"
)

type UserInfoRecord struct {
	created  time.Time
	userInfo *v1alpha1.UserInfo
}

// UserInfoCache is a simple hit or miss cache which is used to reduce calls to
// the apiserver. The client-go cache module and higher level informer caches rely on apiserver
// events to synchronize local caches. Since the clusterstore will update secrets during auth callback,
// we cannot be certain that these updates would have occurred on subsequent requests without
// triggering and waiting on a full resync. Unfortunately, Resync is not exposed on Informer objects,
// thus we need to query the actual apiserver state, instead of relying on the local caches.
type UserInfoCache struct {
	TTL time.Duration

	infos map[string]UserInfoRecord
	lock  sync.Mutex
}

func NewUserInfoCache(ttl time.Duration) *UserInfoCache {
	infos := make(map[string]UserInfoRecord)
	return &UserInfoCache{
		TTL:   ttl,
		infos: infos,
		lock:  sync.Mutex{},
	}
}

func (uc *UserInfoCache) Get(claimsId string) *v1alpha1.UserInfo {
	record, ok := uc.infos[claimsId]
	if !ok {
		return nil
	}

	now := time.Now()
	if now.Sub(record.created.Add(uc.TTL)) >= 0 {
		// expired delete record
		uc.Delete(claimsId)
		return nil
	}
	return record.userInfo
}

func (uc *UserInfoCache) Save(claimsId string, info *v1alpha1.UserInfo) {
	record := UserInfoRecord{
		created:  time.Now(),
		userInfo: info,
	}
	uc.infos[claimsId] = record
	return
}

func (uc *UserInfoCache) Delete(claimsId string) {
	uc.lock.Lock()
	defer uc.lock.Unlock()
	delete(uc.infos, claimsId)
}
