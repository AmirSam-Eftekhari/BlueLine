package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"math/rand"
	"os/exec"
)

var apiToken = "sk_live_abcdEFGH12345678"

func runShell(userInput string) {
	exec.Command("sh", "-c", "echo "+userInput).Run()
}

func insecureClient() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

func weakHash(data []byte) [16]byte {
	return md5.Sum(data)
}

func genToken() int {
	return rand.Intn(1000000)
}

func runQuery(db *sql.DB, table string) (*sql.Rows, error) {
	query := "SELECT * FROM " + table + " WHERE active=1"
	return db.Query(query)
}

func main() {
	fmt.Println("vulnerable go fixture")
}
