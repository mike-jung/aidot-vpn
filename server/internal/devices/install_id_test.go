package devices

import ("strings"; "testing")

func TestInstallIDStorageBoundary(t *testing.T) {
 for _, id := range []string{"", strings.Repeat("x",37), string([]byte{0xff})} {
  if validateInstallID(id)==nil {t.Fatal("invalid install ID accepted")}
 }
 for _, id := range []string{"x", "12345678-1234-1234-1234-123456789012", strings.Repeat("가",36)} {
  if err:=validateInstallID(id);err!=nil {t.Fatal(err)}
 }
}
