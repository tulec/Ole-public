package domain_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"errors"
	"testing"
)

type registrationUserRepo struct {
	*memory.UserRepo
	createErr, lookupErr   error
	createCalls, saveCalls int
}

func (r *registrationUserRepo) Create(u *domain.User) error {
	r.createCalls++
	if r.createErr != nil {
		return r.createErr
	}
	return r.UserRepo.Create(u)
}

func (r *registrationUserRepo) Save(u *domain.User) error {
	r.saveCalls++
	return r.UserRepo.Save(u)
}

func (r *registrationUserRepo) FindByEmail(email string) (*domain.User, error) {
	if r.lookupErr != nil {
		return nil, r.lookupErr
	}
	return r.UserRepo.FindByEmail(email)
}

func TestRegistrationUsesCreateWithoutUpdatingOnConflict(t *testing.T) {
	repo := &registrationUserRepo{UserRepo: memory.NewUserRepo(), createErr: domain.ErrAlreadyExists}
	auth := domain.NewAuthService(repo, nil, nil, "test-secret", "ole-test")
	user, err := auth.Register("new@example.com", "secret")
	if user != nil || !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("got user=%#v err=%v, want create conflict", user, err)
	}
	if repo.createCalls != 1 || repo.saveCalls != 0 {
		t.Fatalf("create calls=%d save calls=%d", repo.createCalls, repo.saveCalls)
	}
}

func TestRegistrationStopsOnLookupFailure(t *testing.T) {
	lookupErr := errors.New("repository unavailable")
	repo := &registrationUserRepo{UserRepo: memory.NewUserRepo(), lookupErr: lookupErr}
	auth := domain.NewAuthService(repo, nil, nil, "test-secret", "ole-test")
	user, err := auth.Register("new@example.com", "secret")
	if user != nil || !errors.Is(err, lookupErr) || repo.createCalls != 0 || repo.saveCalls != 0 {
		t.Fatalf("registration continued after lookup failure: user=%#v err=%v creates=%d saves=%d", user, err, repo.createCalls, repo.saveCalls)
	}
}
