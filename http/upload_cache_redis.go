package fbhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisUploadCache is an upload cache for multi replica deployments
type redisUploadCache struct {
	client *redis.Client
}

func newRedisUploadCache(redisURL string) (*redisUploadCache, error) {
	if redisURL == "" {
		return nil, fmt.Errorf("redis URL is required")
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return &redisUploadCache{client: client}, nil
}

func (c *redisUploadCache) filePathKey(filePath string) string {
	return "filebrowser:upload:" + filePath
}

// Register stores the upload length. The scoped removal callback is unused by
// the redis backend, which does not delete partial files on eviction.
func (c *redisUploadCache) Register(filePath string, fileSize int64, _ func() error) {
	err := c.client.Set(context.Background(), c.filePathKey(filePath), fileSize, uploadCacheTTL).Err()
	if err != nil {
		log.Printf("failed to register upload in redis cache: %v", err)
	}
}

func (c *redisUploadCache) Complete(filePath string) {
	err := c.client.Del(context.Background(), c.filePathKey(filePath)).Err()
	if err != nil {
		log.Printf("failed to complete upload in redis cache: %v", err)
	}
}

func (c *redisUploadCache) GetLength(filePath string) (int64, error) {
	result, err := c.client.Get(context.Background(), c.filePathKey(filePath)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, fmt.Errorf("no active upload found for the given path")
		}
		return 0, fmt.Errorf("redis error: %w", err)
	}

	size, err := strconv.ParseInt(result, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid upload length in cache: %w", err)
	}

	c.Touch(filePath)

	return size, nil
}

func (c *redisUploadCache) Touch(filePath string) {
	err := c.client.Expire(context.Background(), c.filePathKey(filePath), uploadCacheTTL).Err()
	if err != nil {
		log.Printf("failed to touch upload in redis cache: %v", err)
	}
}

func (c *redisUploadCache) Lock(filePath string) (func(), bool, error) {
	var tokenBytes [16]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return nil, false, err
	}
	token := hex.EncodeToString(tokenBytes[:])
	lockKey := c.filePathKey(filePath) + ":lock"
	ctx := context.Background()
	acquired, err := c.client.SetNX(ctx, lockKey, token, uploadCacheTTL).Result()
	if err != nil || !acquired {
		return nil, acquired, err
	}

	stop := make(chan struct{})
	var stopOnce sync.Once
	go func() {
		ticker := time.NewTicker(uploadCacheTTL / 3)
		defer ticker.Stop()
		renew := redis.NewScript(`
			if redis.call("GET", KEYS[1]) == ARGV[1] then
				return redis.call("PEXPIRE", KEYS[1], ARGV[2])
			end
			return 0
		`)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := renew.Run(ctx, c.client, []string{lockKey}, token, uploadCacheTTL.Milliseconds()).Err(); err != nil {
					log.Printf("failed to renew upload lock: %v", err)
				}
			}
		}
	}()

	return func() {
		stopOnce.Do(func() { close(stop) })
		unlock := redis.NewScript(`
			if redis.call("GET", KEYS[1]) == ARGV[1] then
				return redis.call("DEL", KEYS[1])
			end
			return 0
		`)
		if err := unlock.Run(ctx, c.client, []string{lockKey}, token).Err(); err != nil {
			log.Printf("failed to release upload lock: %v", err)
		}
	}, true, nil
}

func (c *redisUploadCache) Close() {
	c.client.Close()
}
