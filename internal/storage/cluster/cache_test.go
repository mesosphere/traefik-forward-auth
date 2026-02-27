package cluster

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mesosphere/traefik-forward-auth/internal/api/storage/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func TestUserInfoCache_ConcurrentAccess(t *testing.T) {
	cache := NewUserInfoCache(time.Minute)

	userInfo := &v1alpha1.UserInfo{
		Username: "user@example.com",
		Email:    "user@example.com",
		Groups:   []string{"group1", "group2"},
	}

	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent Save
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			cache.Save(fmt.Sprintf("key-%d", i), userInfo)
		}(i)
	}

	// Concurrent Get (same keys, racing with Save)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			cache.Get(fmt.Sprintf("key-%d", i))
		}(i)
	}

	// Concurrent Delete (same keys, racing with Save and Get)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			cache.Delete(fmt.Sprintf("key-%d", i))
		}(i)
	}

	wg.Wait()
}

func TestUserInfoCache_TTLExpiry(t *testing.T) {
	cache := NewUserInfoCache(50 * time.Millisecond)

	userInfo := &v1alpha1.UserInfo{Username: "user@example.com"}
	cache.Save("key1", userInfo)

	assert.Equal(t, userInfo, cache.Get("key1"))

	time.Sleep(100 * time.Millisecond)

	assert.Nil(t, cache.Get("key1"), "expected expired entry to return nil")
}

func TestUserInfoCache_DeleteRemovesEntry(t *testing.T) {
	cache := NewUserInfoCache(time.Minute)

	userInfo := &v1alpha1.UserInfo{Username: "user@example.com"}
	cache.Save("key1", userInfo)

	assert.Equal(t, userInfo, cache.Get("key1"))

	cache.Delete("key1")

	assert.Nil(t, cache.Get("key1"), "expected deleted entry to return nil")
}
