package models

import (
	"time"
)

// User represents a registered user account in the system
type User struct {
	ID                  uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	Username            string     `gorm:"type:varchar(64);uniqueIndex;not null" json:"username"`
	PasswordHash        string     `gorm:"type:varchar(255);not null" json:"-"`
	TOTPSecret          string     `gorm:"type:varchar(128)" json:"-"`
	TOTPEnabled         bool       `gorm:"default:false;not null" json:"totp_enabled"`
	FailedLoginAttempts int        `gorm:"default:0;not null" json:"failed_login_attempts"`
	LockedUntil         *time.Time `gorm:"index" json:"locked_until,omitempty"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
	CreatedAt           time.Time  `gorm:"not null" json:"created_at"`
	UpdatedAt           time.Time  `gorm:"not null" json:"updated_at"`

	// Relationships
	Sessions []Session `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// IsLocked checks if the user account is currently locked out
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// LockTemporarily locks the account until the specified duration passes
func (u *User) LockTemporarily(duration time.Duration) {
	unlockTime := time.Now().Add(duration)
	u.LockedUntil = &unlockTime
}

// ResetLockout clears failed login attempts and unlocks the account
func (u *User) ResetLockout() {
	u.FailedLoginAttempts = 0
	u.LockedUntil = nil
}
