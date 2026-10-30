package memory_test

import (
	"Ole/internal/domain"
	"Ole/internal/store/memory"
	"errors"
	"testing"
)

func TestUserCreateRejectsIDAndEmailConflicts(t *testing.T) {
	for _, tc := range []struct {
		name, id, email string
	}{
		{"same ID", "usr-legacy", "other@example.com"},
		{"same email", "usr-other", "OWNER@EXAMPLE.COM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := memory.NewUserRepo()
			original := &domain.User{ID: domain.UserID{Value: "usr-legacy"}, Email: "owner@example.com", PasswordHash: "original", Status: domain.UserStatusActive}
			if err := repo.Save(original); err != nil {
				t.Fatal(err)
			}
			conflict := &domain.User{ID: domain.UserID{Value: tc.id}, Email: tc.email, PasswordHash: "replacement", Status: domain.UserStatusBanned}
			if err := repo.Create(conflict); !errors.Is(err, domain.ErrAlreadyExists) {
				t.Fatalf("create conflict: got %v, want ErrAlreadyExists", err)
			}
			stored, err := repo.FindByID(original.ID)
			if err != nil || stored == nil || *stored != *original {
				t.Fatalf("original user changed: %#v, %v", stored, err)
			}
			if tc.id != original.ID.String() {
				if inserted, _ := repo.FindByID(conflict.ID); inserted != nil {
					t.Fatal("conflicting user was inserted")
				}
			}
		})
	}
}

func TestUserCreateAndUpdatePreserveExistingIDs(t *testing.T) {
	repo := memory.NewUserRepo()
	user := &domain.User{ID: domain.UserID{Value: "usr-1"}, Email: "owner@example.com", PasswordHash: "old", Status: domain.UserStatusActive}
	if err := repo.Create(user); err != nil {
		t.Fatal(err)
	}
	user.PasswordHash = "new"
	if err := repo.Save(user); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.FindByID(user.ID)
	if err != nil || stored == nil || stored.PasswordHash != "new" || stored.ID.String() != "usr-1" {
		t.Fatalf("legacy ID update failed: %#v, %v", stored, err)
	}
}
