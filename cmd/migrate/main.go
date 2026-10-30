package main

import (
	"Ole/internal/config"
	"Ole/internal/store/postgres"
	"context"
	"database/sql"
	"fmt"
	"os"
)

func main() {
	cfg := config.Load()

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		fmt.Println("open database:", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := postgres.Ping(db); err != nil {
		fmt.Println("ping database:", err)
		os.Exit(1)
	}
	if err := postgres.RunMigrations(context.Background(), db, cfg.MigrationsDir); err != nil {
		fmt.Println("run migrations:", err)
		os.Exit(1)
	}

	fmt.Println("migrations applied")
}
