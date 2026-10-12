package db_test

import (
	"context"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestStaffSchemaMigrationTwice(t *testing.T) {
	s := staffSchemaFixture(t)
	ctx := context.Background()
	var versions []int64
	if err := s.Pool.QueryRow(ctx, "select array_agg(version order by version) from schema_versions").Scan(&versions); err != nil {
		t.Fatal("version inventory failed")
	}
	if !reflect.DeepEqual(versions, []int64{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatal("fresh staff migration inventory must be exactly versions 1 through 8")
	}
	requireStaffSchema(t, s)
	inventory := func() []string {
		t.Helper()
		var rows []string
		statement := `select array_agg(entry order by entry) from (
select version::text || ':' || applied_at::text as entry from schema_versions
union all select table_name || ':' || column_name || ':' || data_type || ':' || is_nullable || ':' || coalesce(column_default,'')
from information_schema.columns where table_schema=current_schema()
union all select conname || ':' || pg_get_constraintdef(oid) from pg_constraint where connamespace=current_schema()::regnamespace
union all select indexname || ':' || indexdef from pg_indexes where schemaname=current_schema()) actual`
		if err := s.Pool.QueryRow(ctx, statement).Scan(&rows); err != nil {
			t.Fatal("schema inventory failed")
		}
		return rows
	}
	before := inventory()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal("repeat staff migration failed")
	}
	if !reflect.DeepEqual(before, inventory()) {
		t.Fatal("repeat migration changed schema or version timestamps")
	}
}

func TestStaffSchemaCredentialAndChallengeConstraints(t *testing.T) {
	s := staffSchemaFixture(t)
	requireStaffSchema(t, s)
	tx := transaction(t, s)
	instance := id(t)
	exec(t, tx, "insert into app_instance(id) values($1)", instance)
	principal := staffSchemaCredential(t, tx, instance, "owner", "Operator.One")
	staffSchemaFactor(t, tx, instance, principal, 1)
	for _, username := range []string{"ab", "spaces forbidden", "unicode_é", "abcdefghijklmnopqrstuvwxyz1234567"} {
		rejectStaffSchema(t, tx, "23514", "update auth_staff_credentials set username=$2 where principal_id=$1", principal, username)
	}
	for _, statement := range []string{
		"update auth_staff_credentials set password_hash='plaintext' where principal_id=$1",
		"update auth_staff_credentials set credential_epoch=0 where principal_id=$1",
		"update auth_staff_credentials set factor_version=0 where principal_id=$1",
		"update auth_staff_credentials set role='participant' where principal_id=$1",
		"update auth_staff_factors set last_totp_counter=-2 where principal_id=$1",
		"update auth_staff_factors set encrypted_seed=decode(repeat('00',59),'hex') where principal_id=$1",
		"update auth_staff_factors set encrypted_seed=decode(repeat('00',61),'hex') where principal_id=$1",
	} {
		rejectStaffSchema(t, tx, "23514", statement, principal)
	}
	other := id(t)
	exec(t, tx, "insert into auth_principals(id,role) values($1,'admin')", other)
	rejectStaffSchema(t, tx, "23505", `insert into auth_staff_credentials(instance_id,principal_id,role,username,password_hash)
select instance_id,$2,'admin','operator.one',password_hash from auth_staff_credentials where principal_id=$1`, principal, other)
	challenge := id(t)
	exec(t, tx, `insert into auth_staff_challenges(id,instance_id,principal_id,target_role,kind,token_hash,factor_version,credential_epoch,created_at,expires_at)
values($1,$2,$3,'owner','login',decode(repeat('11',32),'hex'),1,1,now(),now()+interval '5 minutes')`, challenge, instance, principal)
	for _, statement := range []string{
		"update auth_staff_challenges set kind='grant_owner' where id=$1",
		"update auth_staff_challenges set token_hash=decode(repeat('11',31),'hex') where id=$1",
		"update auth_staff_challenges set expires_at=created_at+interval '6 minutes' where id=$1",
		"update auth_staff_challenges set expires_at=created_at where id=$1",
		"update auth_staff_challenges set consumed_at=created_at-interval '1 second' where id=$1",
		"update auth_staff_challenges set consumed_at=expires_at+interval '1 second' where id=$1",
		"update auth_staff_challenges set credential_epoch=0 where id=$1",
		"update auth_staff_challenges set factor_version=0 where id=$1",
		"update auth_staff_challenges set encrypted_seed=decode(repeat('00',60),'hex') where id=$1",
		"update auth_staff_challenges set kind='admin_enroll' where id=$1",
		"update auth_staff_challenges set kind='step_up' where id=$1",
	} {
		rejectStaffSchema(t, tx, "23514", statement, challenge)
	}
	exec(t, tx, `insert into auth_staff_recovery(instance_id,principal_id,factor_version,slot,code_hash)
values($1,$2,1,1,decode(repeat('22',32),'hex'))`, instance, principal)
	rejectStaffSchema(t, tx, "23514", "update auth_staff_recovery set slot=11 where principal_id=$1", principal)
	rejectStaffSchema(t, tx, "23514", "update auth_staff_recovery set code_hash=decode(repeat('22',31),'hex') where principal_id=$1", principal)
	exec(t, tx, `insert into auth_staff_rates(instance_id,key_hash,kind,attempts,window_started_at,expires_at)
values($1,decode(repeat('33',32),'hex'),'login_account',1,now(),now()+interval '1 minute')`, instance)
	rejectStaffSchema(t, tx, "23514", "update auth_staff_rates set attempts=-1 where instance_id=$1", instance)
	rejectStaffSchema(t, tx, "23514", "update auth_staff_rates set key_hash=decode(repeat('33',31),'hex') where instance_id=$1", instance)
}

func TestStaffSchemaFactorVersionBinding(t *testing.T) {
	s := staffSchemaFixture(t)
	requireStaffSchema(t, s)
	tx := transaction(t, s)
	instance, session := id(t), id(t)
	exec(t, tx, "insert into app_instance(id) values($1)", instance)
	owner := staffSchemaCredential(t, tx, instance, "owner", "owner.one")
	admin := staffSchemaCredential(t, tx, instance, "admin", "admin.one")
	staffSchemaFactor(t, tx, instance, owner, 1)
	staffSchemaFactor(t, tx, instance, admin, 1)
	exec(t, tx, `insert into auth_sessions(id,principal_id,token_hash,created_at,expires_at,mfa_verified_at)
values($1,$2,decode(repeat('44',32),'hex'),now(),now()+interval '30 minutes',now())`, session, owner)
	insert := `insert into auth_staff_attestations(session_id,instance_id,principal_id,factor_version,credential_epoch,session_created_at,session_expires_at,verified_at)
select id,$2,$3,$4,1,created_at,expires_at,created_at from auth_sessions where id=$1`
	rejectStaffSchema(t, tx, "23503", insert, session, instance, admin, int64(1))
	rejectStaffSchema(t, tx, "23503", insert, session, instance, owner, int64(2))
	rejectStaffSchema(t, tx, "23503", insert, session, id(t), owner, int64(1))
	exec(t, tx, insert, session, instance, owner, int64(1))
	rejectStaffSchema(t, tx, "23514", "update auth_staff_attestations set verified_at=session_expires_at+interval '1 second' where session_id=$1", session)
	rejectStaffSchema(t, tx, "23514", "update auth_staff_attestations set verified_at=session_created_at-interval '1 second' where session_id=$1", session)
	rejectStaffSchema(t, tx, "23503", "update auth_staff_attestations set session_created_at=session_created_at-interval '1 second' where session_id=$1", session)
	rejectStaffSchema(t, tx, "23503", "update auth_staff_credentials set factor_version=2 where principal_id=$1", owner)
	rejectStaffSchema(t, tx, "23503", `insert into auth_staff_recovery(instance_id,principal_id,factor_version,slot,code_hash)
values($1,$2,2,1,decode(repeat('55',32),'hex'))`, instance, owner)
	rejectStaffSchema(t, tx, "23503", "update auth_principals set role='admin' where id=$1", owner)
	challenge := id(t)
	exec(t, tx, `insert into auth_staff_challenges(id,instance_id,principal_id,target_role,kind,token_hash,factor_version,credential_epoch,created_at,expires_at,session_id)
values($1,$2,$3,'owner','step_up',decode(repeat('66',32),'hex'),1,1,now(),now()+interval '5 minutes',$4)`, challenge, instance, owner, session)
	rejectStaffSchema(t, tx, "23503", "update auth_staff_challenges set principal_id=$2,target_role='admin' where id=$1", challenge, admin)
	// Historical proof must survive rotation without being rewritten into the new factor.
	exec(t, tx, "update auth_staff_factors set revoked_at=now() where principal_id=$1 and factor_version=1", owner)
	staffSchemaFactor(t, tx, instance, owner, 2)
	var attested, current int64
	if err := tx.QueryRow(context.Background(), `select a.factor_version,c.factor_version
from auth_staff_attestations a join auth_staff_credentials c on c.principal_id=a.principal_id where a.session_id=$1`, session).Scan(&attested, &current); err != nil || attested != 1 || current != 2 {
		t.Fatal("rotation lost historical factor binding")
	}
}

func TestStaffSchemaNoPlaintextSecrets(t *testing.T) {
	s := staffSchemaFixture(t)
	requireStaffSchema(t, s)
	ctx := context.Background()
	var columns int
	statement := `select count(*) from information_schema.columns where table_schema=current_schema()
and table_name in ('auth_bootstrap','auth_staff_credentials','auth_staff_factors','auth_staff_challenges','auth_staff_recovery','auth_staff_rates','auth_staff_attestations')
and column_name in ('password','seed','secret','totp_seed','recovery_code','token','capability','peer','payload')`
	if err := s.Pool.QueryRow(ctx, statement).Scan(&columns); err != nil || columns != 0 {
		t.Fatal("raw authentication material columns are forbidden")
	}
	for _, binding := range [][2]string{{"auth_bootstrap", "token_hash"}, {"auth_staff_challenges", "token_hash"}, {"auth_staff_recovery", "code_hash"}, {"auth_staff_rates", "key_hash"}, {"auth_staff_factors", "encrypted_seed"}, {"auth_staff_challenges", "encrypted_seed"}} {
		var binary bool
		if err := s.Pool.QueryRow(ctx, `select data_type='bytea' from information_schema.columns
where table_schema=current_schema() and table_name=$1 and column_name=$2`, binding[0], binding[1]).Scan(&binary); err != nil || !binary {
			t.Fatal("seed/digest persistence must use the constrained binary column")
		}
	}
	tx := transaction(t, s)
	instance := id(t)
	exec(t, tx, "insert into app_instance(id) values($1)", instance)
	principal := staffSchemaCredential(t, tx, instance, "owner", "private.owner")
	staffSchemaFactor(t, tx, instance, principal, 1)
	rejectStaffSchema(t, tx, "23514", "update auth_staff_factors set encrypted_seed=convert_to('not an encrypted seed','UTF8') where principal_id=$1", principal)
	rejectStaffSchema(t, tx, "23514", "update auth_staff_credentials set password_hash='not a salted password hash' where principal_id=$1", principal)
}

func TestStaffSchemaBootstrapSingleton(t *testing.T) {
	s := staffSchemaFixture(t)
	requireStaffSchema(t, s)
	tx := transaction(t, s)
	instance := id(t)
	exec(t, tx, "insert into app_instance(id) values($1)", instance)
	rejectStaffSchema(t, tx, "23505", "insert into app_instance(id) values($1)", id(t))
	rejectStaffSchema(t, tx, "23514", "insert into app_instance(singleton,id) values(false,$1)", id(t))
	exec(t, tx, `insert into auth_bootstrap(instance_id,token_hash,created_at,expires_at)
values($1,decode(repeat('77',32),'hex'),now(),now()+interval '10 minutes')`, instance)
	rejectStaffSchema(t, tx, "23505", `insert into auth_bootstrap(instance_id,token_hash,created_at,expires_at)
values($1,decode(repeat('88',32),'hex'),now(),now()+interval '10 minutes')`, instance)
	rejectStaffSchema(t, tx, "23514", "update auth_bootstrap set expires_at=created_at+interval '11 minutes' where instance_id=$1", instance)
	rejectStaffSchema(t, tx, "23514", "update auth_bootstrap set token_hash=decode(repeat('77',31),'hex') where instance_id=$1", instance)
	rejectStaffSchema(t, tx, "23503", "update auth_bootstrap set instance_id=$2 where instance_id=$1", instance, id(t))
}

func TestStaffSchemaOperationsNullIsUnknown(t *testing.T) {
	s := staffSchemaFixture(t)
	requireStaffSchema(t, s)
	tx := transaction(t, s)
	instance := id(t)
	exec(t, tx, "insert into app_instance(id) values($1)", instance)
	exec(t, tx, "insert into app_operating_state(instance_id) values($1)", instance)
	read := func() [3]*time.Time {
		t.Helper()
		var heartbeat, success, backup *time.Time
		if err := tx.QueryRow(context.Background(), `select worker_heartbeat_at,last_job_success_at,last_checked_backup_at
from app_operating_state where instance_id=$1`, instance).Scan(&heartbeat, &success, &backup); err != nil {
			t.Fatal("operating observations read failed")
		}
		return [3]*time.Time{heartbeat, success, backup}
	}
	if observed := read(); observed != [3]*time.Time{} {
		t.Fatal("new operating state fabricated an observation")
	}
	exec(t, tx, "update app_operating_state set worker_heartbeat_at=clock_timestamp() where instance_id=$1", instance)
	if observed := read(); observed[0] == nil || observed[1] != nil || observed[2] != nil {
		t.Fatal("heartbeat fabricated successful work or checked backup")
	}
	rejectStaffSchema(t, tx, "23503", "update app_operating_state set instance_id=$2 where instance_id=$1", instance, id(t))
	var stored string
	if err := tx.QueryRow(context.Background(), "select id::text from app_instance").Scan(&stored); err != nil || stored != instance {
		t.Fatal("logical instance was not independently persisted")
	}
}

func TestStaffSchemaNamedQueries(t *testing.T) {
	s := staffSchemaFixture(t)
	content, err := os.ReadFile("../../db/queries/staff_identity.sql")
	if err != nil {
		t.Fatal("reviewed staff query source is absent")
	}
	header := regexp.MustCompile(`(?m)^-- name: ([A-Za-z][A-Za-z0-9]*) :(?:one|exec|execrows)\r?$`)
	matches := header.FindAllStringSubmatchIndex(string(content), -1)
	statements := make(map[string]string)
	for i, match := range matches {
		end := len(content)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		name := string(content[match[2]:match[3]])
		if _, duplicate := statements[name]; duplicate {
			t.Fatal("duplicate named staff query")
		}
		statements[name] = strings.TrimSpace(string(content[match[1]:end]))
	}
	expected := []string{"ReadLogicalInstance", "LockLogicalInstance", "CreateLogicalInstance", "LockBootstrap", "WriteBootstrap", "ConsumeBootstrap", "CloseBootstrap", "ReadStaffCredential", "LockStaffCredential", "LockStaffUsername", "CreateStaffCredential", "SetStaffPassword", "ActivateStaffFactor", "LockStaffFactor", "CreateStaffFactor", "AcceptStaffFactorCounter", "RevokeStaffFactors", "CreateStaffChallenge", "LockStaffChallenge", "ConsumeStaffChallenge", "RevokeStaffChallenges", "CreateStaffRecovery", "ConsumeStaffRecovery", "RevokeStaffRecovery", "CreateStaffAttestation", "ReadStaffAttestation", "IncrementStaffRate", "LockStaffRate", "ReadOperatingState", "ObserveWorkerHeartbeat", "ObserveJobSuccess", "ObserveCheckedBackup"}
	if len(statements) != len(expected) {
		t.Fatal("named staff query inventory is incomplete")
	}
	conn, err := s.Pool.Acquire(context.Background())
	if err != nil {
		t.Fatal("query preparation connection failed")
	}
	defer conn.Release()
	for _, name := range expected {
		statement, exists := statements[name]
		if !exists || statement == "" {
			t.Fatal("required named query absent:", name)
		}
		if _, err := conn.Conn().Prepare(context.Background(), "schema_probe_"+name, statement); err != nil {
			t.Fatal("named query does not prepare against the actual schema:", name)
		}
	}
	tx := transaction(t, s)
	instance, key := id(t), make([]byte, 32)
	exec(t, tx, statements["CreateLogicalInstance"], instance)
	var stored string
	if err := tx.QueryRow(context.Background(), statements["ReadLogicalInstance"]).Scan(&stored); err != nil || stored != instance {
		t.Fatal("logical instance query did not read the persisted identity")
	}
	var now time.Time
	if err := tx.QueryRow(context.Background(), "select clock_timestamp()").Scan(&now); err != nil {
		t.Fatal("database clock failed")
	}
	exec(t, tx, statements["ObserveWorkerHeartbeat"], instance, now)
	var heartbeat, success, backup *time.Time
	if err := tx.QueryRow(context.Background(), statements["ReadOperatingState"], instance).Scan(&heartbeat, &success, &backup); err != nil || heartbeat == nil || success != nil || backup != nil {
		t.Fatal("named heartbeat/query fabricated job or backup success")
	}
	var attempts int
	for _, want := range []int{1, 2} {
		if err := tx.QueryRow(context.Background(), statements["IncrementStaffRate"], instance, key, "login_account", now, now.Add(time.Minute)).Scan(&attempts); err != nil || attempts != want {
			t.Fatal("durable rate query failed to increment the actual bucket")
		}
	}
	if err := tx.QueryRow(context.Background(), statements["IncrementStaffRate"], instance, key, "login_account", now.Add(2*time.Minute), now.Add(3*time.Minute)).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatal("expired rate bucket did not restart from one")
	}
}
