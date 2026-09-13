package devices

import (
 "errors"
 "unicode/utf8"
)

// The enrollment queue must accept only IDs the device table can store.
func validateInstallID(id string) error {
 n := utf8.RuneCountInString(id)
 if !utf8.ValidString(id) || n < 1 || n > 36 {
  return errors.New("install_id must contain 1 to 36 characters")
 }
 return nil
}
