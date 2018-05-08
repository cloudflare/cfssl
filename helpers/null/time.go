package null

import (
	"database/sql/driver"
	"fmt"
	"time"
)

// Time is a nullable time.Time, a la pq.Time or mysql.Time.
type Time struct {
	Time  time.Time
	Valid bool
}

// Scan implements the Scanner interface.
func (t *Time) Scan(value interface{}) error {
	var err error
	switch x := value.(type) {
	case time.Time:
		t.Time, t.Valid = x, true
	case nil:
		t.Time, t.Valid = time.Time{}, false
		return nil
	default:
		err = fmt.Errorf("null: cannot scan type %T into Time: %v", value, value)
		t.Time, t.Valid = time.Time{}, false
	}
	return err
}

// Value implements the driver Valuer interface.
func (t Time) Value() (driver.Value, error) {
	if !t.Valid {
		return nil, nil
	}
	return t.Time, nil
}

// NewNTime creates a new Time.
func NewTime(t time.Time, valid bool) Time {
	return Time{
		Time:  t,
		Valid: valid,
	}
}

// TimeFrom creates a new Time that will always be valid.
func TimeFrom(t time.Time) Time {
	return NewTime(t, !t.IsZero())
}

// TimeFromPtr creates a new Time that will be null if t is nil.
func TimeFromPtr(t *time.Time) Time {
	if t == nil {
		return NewTime(time.Time{}, false)
	}
	return NewTime(*t, !t.IsZero())
}

// SetTime changes this Time's value and sets it to be non-null if time is not zero, otherwise
// time is set to be null.
func (t *Time) SetTime(v time.Time) {
	t.Time = v
	t.Valid = !v.IsZero()
}

// Ptr returns a pointer to this Time's value, or a nil pointer if this Time is null.
func (t Time) Ptr() *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

// ValueOrZero returns the time if valid, otherwise zero.
func (t Time) ValueOrZero() time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time
}

// IsZero returns true for null times.
func (t Time) IsZero() bool {
	return !t.Valid
}
