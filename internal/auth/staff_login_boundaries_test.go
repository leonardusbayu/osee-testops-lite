package auth

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"osee-testops-lite/db/queries"
)

func TestStaffRatePersistsAcrossRestart(t *testing.T) {
	t.Run("five_account_failures_five_minutes", func(t *testing.T) {
		f := staffLoginFixture(t)
		ctx := context.Background()
		for range 5 {
			if _, err := f.identity.BeginLogin(ctx, f.username, staffCryptoPassword(t), "198.51.100.21"); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("invalid password did not use the durable failure budget")
			}
		}
		restarted, err := NewStaffIdentity(NewService(f.store, nil), f.key, f.instance)
		if err != nil {
			t.Fatal("same logical instance restart failed")
		}
		restarted.now = f.identity.now
		if _, err = restarted.BeginLogin(ctx, f.username, f.password, "198.51.100.22"); !errors.Is(err, ErrRateLimited) {
			t.Fatal("restart or new peer bypassed five failed account attempts")
		}
		restarted.now = func() time.Time { return f.at.Add(5 * time.Minute) }
		if _, err = restarted.BeginLogin(ctx, f.username, f.password, "198.51.100.22"); err != nil {
			t.Fatal("account gate did not expire at the five-minute boundary")
		}
	})
	t.Run("ten_peer_attempts_one_minute", func(t *testing.T) {
		f := staffLoginFixture(t)
		ctx := context.Background()
		for index := range 10 {
			if _, err := f.identity.BeginLogin(ctx, fmt.Sprintf("unknown.%d", index), f.password, "198.51.100.31"); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("unknown username did not fail generically within peer budget")
			}
		}
		restarted, err := NewStaffIdentity(NewService(f.store, nil), f.key, f.instance)
		if err != nil {
			t.Fatal("same logical instance restart failed")
		}
		restarted.now = f.identity.now
		if _, err = restarted.BeginLogin(ctx, f.username, f.password, "198.51.100.31"); !errors.Is(err, ErrRateLimited) {
			t.Fatal("restart bypassed ten attempts per peer per minute")
		}
		restarted.now = func() time.Time { return f.at.Add(time.Minute) }
		if _, err = restarted.BeginLogin(ctx, f.username, f.password, "198.51.100.31"); err != nil {
			t.Fatal("peer gate did not expire at the one-minute boundary")
		}
	})
	t.Run("socket_peer_not_forwarded_header", func(t *testing.T) {
		f := staffLoginFixture(t)
		ctx := context.Background()
		for index := range 10 {
			r := staffCookieRequest(SessionCookieName, f.session.Token)
			r.RemoteAddr = "198.51.100.41:54321"
			r.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", index+1))
			if _, err := f.identity.BeginLogin(ctx, fmt.Sprintf("unknown.%d", index), f.password, peerIP(r)); !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("synthetic socket-peer login attempt failed outside generic rejection")
			}
		}
		r := staffCookieRequest(SessionCookieName, f.session.Token)
		r.RemoteAddr = "198.51.100.41:54322"
		r.Header.Set("X-Forwarded-For", "203.0.113.200")
		if _, err := f.identity.BeginLogin(ctx, f.username, f.password, peerIP(r)); !errors.Is(err, ErrRateLimited) {
			t.Fatal("changing a forwarded header bypassed the actual peer gate")
		}
	})
}

func TestStaffDerivationConcurrencyBound(t *testing.T) {
	f := staffLoginFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	staffPasswordSlots <- struct{}{}
	staffPasswordSlots <- struct{}{}
	held := 2
	defer func() {
		for held > 0 {
			<-staffPasswordSlots
			held--
		}
	}()
	results := make(chan error, 3)
	for index := range 3 {
		go func(index int) {
			_, err := f.identity.BeginLogin(ctx, f.username, f.password, fmt.Sprintf("198.51.100.%d", 61+index))
			results <- err
		}(index)
	}
	select {
	case <-results:
		t.Fatal("real login bypassed both occupied password-derivation slots")
	case <-time.After(150 * time.Millisecond):
	}
	<-staffPasswordSlots
	held--
	for range 3 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal("bounded real derivation failed after one slot became available")
			}
		case <-ctx.Done():
			t.Fatal("derivation did not leave its bounded wait")
		}
	}
}

func TestStaffPostLockExpiryAndVersionRevocation(t *testing.T) {
	for _, change := range []string{"expiry", "epoch", "disabled"} {
		t.Run(change, func(t *testing.T) {
			f := staffLoginFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			pending, err := f.identity.BeginLogin(ctx, f.username, f.password, "198.51.100.71")
			if err != nil {
				t.Fatal("real login challenge setup failed")
			}
			var clock atomic.Int64
			clock.Store(f.at.UnixNano())
			f.identity.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			code := staffSyntheticCode(t, f.view, f.at)
			tx, err := f.store.Pool.Begin(ctx)
			if err != nil {
				t.Fatal("synthetic decision lock unavailable")
			}
			defer tx.Rollback(context.Background())
			var instance string
			if err = tx.QueryRow(ctx, queries.LockLogicalInstance).Scan(&instance); err != nil {
				t.Fatal("synthetic logical instance lock failed")
			}
			results := make(chan error, 1)
			go func() { _, err := f.identity.ConfirmLogin(ctx, pending.Token, code, ""); results <- err }()
			deadline := time.Now().Add(3 * time.Second)
			waited := false
			for time.Now().Before(deadline) {
				if err = f.store.Pool.QueryRow(ctx, "select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like '%app_instance%' and pid<>pg_backend_pid())").Scan(&waited); err != nil {
					t.Fatal("actual decision-lock observation failed")
				}
				if waited {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !waited {
				t.Fatal("login did not block on the actual persisted instance lock")
			}
			switch change {
			case "expiry":
				clock.Store(f.at.Add(5 * time.Minute).UnixNano())
			case "epoch":
				_, err = tx.Exec(ctx, "update auth_staff_credentials set credential_epoch=credential_epoch+1")
			case "disabled":
				_, err = tx.Exec(ctx, "update auth_principals set enabled=false where role='owner'")
			}
			if err != nil {
				t.Fatal("synthetic post-lock revocation failed")
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal("synthetic decision lock release failed")
			}
			select {
			case err = <-results:
				if !errors.Is(err, ErrUnauthenticated) {
					t.Fatal("expired or revoked challenge survived the actual lock wait")
				}
			case <-ctx.Done():
				t.Fatal("confirmation exceeded its bounded lock wait")
			}
			var consumed, sessions int
			if err = f.store.Pool.QueryRow(context.Background(), `select (select count(*) from auth_staff_challenges where kind='login' and consumed_at is not null),(select count(*) from auth_sessions)`).Scan(&consumed, &sessions); err != nil || consumed != 0 || sessions != 1 {
				t.Fatal("post-lock rejection committed new authority")
			}
		})
	}
}
