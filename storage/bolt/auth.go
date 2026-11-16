package bolt

import (
	"errors"
	"time"

	"github.com/asdine/storm/v3"
	"github.com/asdine/storm/v3/q"

	"github.com/filebrowser/filebrowser/v2/auth"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
)

type authBackend struct {
	db *storm.DB
}

func (s authBackend) Get(t settings.AuthMethod) (auth.Auther, error) {
	var auther auth.Auther

	switch t {
	case auth.MethodJSONAuth:
		auther = &auth.JSONAuth{}
	case auth.MethodProxyAuth:
		auther = &auth.ProxyAuth{}
	case auth.MethodHookAuth:
		auther = &auth.HookAuth{}
	case auth.MethodNoAuth:
		auther = &auth.NoAuth{}
	default:
		return nil, fberrors.ErrInvalidAuthMethod
	}

	return auther, get(s.db, "auther", auther)
}

func (s authBackend) Save(a auth.Auther) error {
	return save(s.db, "auther", a)
}

func (s authBackend) SaveSession(session auth.Session) error {
	return s.db.Save(&session)
}

func (s authBackend) GetSession(id string) (*auth.Session, error) {
	session := &auth.Session{}
	if err := s.db.One("ID", id, session); err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil, fberrors.ErrNotExist
		}
		return nil, err
	}
	return session, nil
}

func (s authBackend) DeleteSession(id string) error {
	err := s.db.DeleteStruct(&auth.Session{ID: id})
	if errors.Is(err, storm.ErrNotFound) {
		return nil
	}
	return err
}

func (s authBackend) DeleteExpiredSessions(before time.Time) error {
	return s.db.Select(q.Lt("ExpiresAt", before.Unix())).Delete(&auth.Session{})
}
