package utils

import (
	"database/sql"
	"errors"
)

type sqlUtil struct{}

// SQL provides access to SQL helper methods
var SQL = sqlUtil{}

// ErrTooManyRows is returned if there are too many rows returned by the query
var ErrTooManyRows = errors.New("Too many database entries were found for the query")

// GetSingle gets a single set of destination parameters from a set of rows. If there are no rows,
// false is returned. If there is more than one row, an error is returned.
func (u *sqlUtil) GetSingle(rows *sql.Rows, dest ...interface{}) (bool, error) {
	found := 0
	for rows.Next() {
		found++
		if found > 1 {
			return false, ErrTooManyRows
		}

		err := rows.Scan(dest)
		if err != nil {
			return false, err
		}
	}

	if found == 0 {
		return false, nil
	}

	return true, nil
}
