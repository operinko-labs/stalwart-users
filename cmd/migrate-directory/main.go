package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(value string) error {
	*l = append(*l, value)

	return nil
}

func main() {
	apply := flag.Bool("apply", false, "write the changes (default is a dry run)")
	var only listFlag
	flag.Var(&only, "only", "limit to this account address (repeatable)")
	flag.Parse()

	if err := execute(*apply, only); err != nil {
		log.Fatalf("migrate-directory: %v", err)
	}
}

func execute(apply bool, only []string) error {
	var env [3]string
	for i, name := range []string{"DATABASE_URL", "STALWART_URL", "STALWART_ADMIN_TOKEN"} {
		if env[i] = os.Getenv(name); env[i] == "" {
			return fmt.Errorf("%s is required", name)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	db, err := sql.Open("postgres", env[0])
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	sqlAccts, err := loadSQL(db)
	if err != nil {
		return err
	}

	client := stalwart.NewClient(env[1], env[2])
	accts, err := client.ListAccounts(ctx)
	if err != nil {
		return err
	}
	domains, err := client.ListDomains(ctx)
	if err != nil {
		return err
	}

	if !apply {
		fmt.Println("Dry run: nothing will be written. Pass --apply to write.")
	}
	if err := run(ctx, os.Stdout, sqlAccts, accts, domains, client, apply, only); err != nil {
		return err
	}
	if apply {
		fmt.Println("Every account's secret was written again, whether or not its line says unchanged.")
	}

	return nil
}
