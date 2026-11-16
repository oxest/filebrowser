package auth

import (
	"sync"
	"time"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// StorageBackend is a storage backend for auth storage.
type StorageBackend interface {
	Get(settings.AuthMethod) (Auther, error)
	Save(Auther) error
	SaveSession(Session) error
	GetSession(string) (*Session, error)
	DeleteSession(string) error
	DeleteExpiredSessions(time.Time) error
}

// Session records a live login token so it can be revoked and renewed once.
type Session struct {
	ID        string `storm:"id"`
	UserID    uint   `storm:"index"`
	ExpiresAt int64  `storm:"index"`
}

// Storage is a auth storage.
type Storage struct {
	back       StorageBackend
	users      *users.Storage
	sessionsMu sync.Mutex
}

// NewStorage creates a auth storage from a backend.
func NewStorage(back StorageBackend, userStore *users.Storage) *Storage {
	return &Storage{back: back, users: userStore}
}

// Get wraps a StorageBackend.Get.
func (s *Storage) Get(t settings.AuthMethod) (Auther, error) {
	return s.back.Get(t)
}

// Save wraps a StorageBackend.Save.
func (s *Storage) Save(a Auther) error {
	return s.back.Save(a)
}

func (s *Storage) SaveSession(session Session) error {
	return s.back.SaveSession(session)
}

func (s *Storage) GetSession(id string) (*Session, error) {
	return s.back.GetSession(id)
}

func (s *Storage) DeleteSession(id string) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	return s.back.DeleteSession(id)
}

// ConsumeSession revokes a session once. Renewal calls use this so concurrent
// requests cannot both redeem the same token.
func (s *Storage) ConsumeSession(id string) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if _, err := s.back.GetSession(id); err != nil {
		return err
	}
	return s.back.DeleteSession(id)
}

func (s *Storage) DeleteExpiredSessions(before time.Time) error {
	return s.back.DeleteExpiredSessions(before)
}
