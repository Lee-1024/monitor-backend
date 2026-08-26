package coroot

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

type Cache struct {
	client  *redis.Client
	prefix  string
	enabled bool
}

func NewCache(raw interface{}, enabled bool) *Cache {
	client, ok := raw.(*redis.Client)
	if !ok || client == nil {
		return &Cache{enabled: false}
	}
	return &Cache{client: client, prefix: "coroot:", enabled: enabled}
}

func (c *Cache) Get(ctx context.Context, key string, target interface{}) (bool, time.Time, error) {
	if c == nil || !c.enabled || c.client == nil {
		return false, time.Time{}, nil
	}
	payload, err := c.client.Get(ctx, c.prefix+key).Bytes()
	if err == redis.Nil {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, err
	}
	var item struct {
		CachedAt time.Time       `json:"cached_at"`
		Data     json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(payload, &item); err != nil {
		return false, time.Time{}, err
	}
	if err := json.Unmarshal(item.Data, target); err != nil {
		return false, time.Time{}, err
	}
	return true, item.CachedAt, nil
}

func (c *Cache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if c == nil || !c.enabled || c.client == nil {
		return nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		CachedAt time.Time       `json:"cached_at"`
		Data     json.RawMessage `json:"data"`
	}{time.Now(), data})
	if err != nil {
		return err
	}
	return c.client.Set(ctx, c.prefix+key, payload, ttl).Err()
}
