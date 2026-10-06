package store

import (
	_ "database/sql"
	"fmt"
	"os/exec"

	ldap "github.com/go-ldap/ldap/v3"
)

func Run(q string) {
	exec.Command("sh", "-c", q).Run()
}

type LdapClient struct{ Base, Filter string }

func (c *LdapClient) Lookup(user string, attrs []string) (string, error) {
	req := ldap.NewSearchRequest(c.Base, 2, 0, 0, 0, false,
		fmt.Sprintf(c.Filter, user), attrs, nil)
	_ = req
	return "", nil
}

type SafeClient struct{ Base, Filter string }

func (c *SafeClient) Lookup(user string, attrs []string) (string, error) {
	u := ldap.EscapeFilter(user)
	req := ldap.NewSearchRequest(c.Base, 2, 0, 0, 0, false,
		fmt.Sprintf(c.Filter, u), attrs, nil)
	_ = req
	return "", nil
}

type DB interface {
	Exec(q string, args ...interface{}) error
	Prepare(q string) (Stmt, error)
}
type Stmt interface {
	Exec(args ...interface{}) error
}

type Repo struct {
	db   DB
	name string
}

// prepared statement: the parameter is a bind argument, not SQL text
func (r *Repo) Delete(id string) {
	stmt, _ := r.db.Prepare("delete from t where id = ?")
	stmt.Exec(id)
}

// field that shares the parameter's name: r.name is not the parameter
func (r *Repo) Rename(name string) {
	r.db.Exec("update t set n = '" + r.name + "'")
	_ = name
}

// string-built SQL from the parameter
func (r *Repo) Find(name string) {
	r.db.Exec("select * from t where n = '" + name + "'")
}
