package main

import (
	"crypto/rsa"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"sync"
)

type DB struct {
	ptr *sql.DB
	mtx sync.Mutex
}

type User struct {
	Id     int
	Access bool
	Uid    string
	PrvKey string
}

func DBInit(filename string) *DB {
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return nil
	}
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS users (
	id INTEGER,
	access BOOLEAN,
	uid VARCHAR(255) UNIQUE,
	prvkey VARCHAR(4096),
	PRIMARY KEY(id)
);
`)
	if err != nil {
		return nil
	}
	return &DB{
		ptr: db,
	}
}

func (db *DB) UpdateAccess(id string, mode bool) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"UPDATE users SET access=$1 WHERE id=$2",
		mode,
		id,
	)
	return err
}

func (db *DB) GetUserByID(id int) *User {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var (
		access bool
		uid    string
		prvkey string
	)
	row := db.ptr.QueryRow(
		"SELECT access, uid, prvkey FROM users WHERE id=$1",
		id,
	)
	row.Scan(&access, &uid, &prvkey)
	if prvkey == "" {
		return nil
	}
	return &User{
		Id:     id,
		Access: access,
		Uid:    uid,
		PrvKey: string(HexDecode(prvkey)),
	}
}

func (db *DB) Size() int {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var id int
	row := db.ptr.QueryRow(
		"SELECT id FROM users ORDER BY id DESC LIMIT 1",
	)
	row.Scan(&id)
	return id
}

func (db *DB) SetKey(uid string, key *rsa.PrivateKey) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"INSERT INTO users (access, uid, prvkey) VALUES ($1, $2, $3)",
		0,
		uid,
		HexEncode(BytesPrivate(key)),
	)
	return err
}

func (db *DB) GetKey(uid string) *rsa.PrivateKey {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var strprv string
	row := db.ptr.QueryRow(
		"SELECT prvkey FROM users WHERE access=1 AND uid=$1",
		uid,
	)
	row.Scan(&strprv)
	return ParsePrivate(HexDecode(strprv))
}
