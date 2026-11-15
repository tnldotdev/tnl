package state

import "github.com/jackc/pgx/v5/pgtype"

func nullableText(value string) pgtype.Text {
	if value == "" {
		return pgtype.Text{}
	}
	return text(value)
}
