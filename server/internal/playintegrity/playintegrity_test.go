package playintegrity

import (
	"context"
	"testing"
)

// stubDecoder returns a fixed payload — lets tests construct any verdict
// shape without touching Google's API.
func stubDecoder(payload *TokenPayload) Decoder {
	return func(_ context.Context, _ string) (*TokenPayload, error) {
		return payload, nil
	}
}

func payloadOK() *TokenPayload {
	p := &TokenPayload{}
	p.RequestDetails.RequestPackageName = "com.aidotvpn.client.app"
	p.RequestDetails.Nonce = "test-nonce-1"
	p.AppIntegrity.AppRecognitionVerdict = "PLAY_RECOGNIZED"
	p.AppIntegrity.PackageName = "com.aidotvpn.client.app"
	p.DeviceIntegrity.DeviceRecognitionVerdict = []string{"MEETS_DEVICE_INTEGRITY"}
	return p
}

func TestVerify_OK(t *testing.T) {
	v, _ := New(Config{
		Decoder:             stubDecoder(payloadOK()),
		ExpectedPackageName: "com.aidotvpn.client.app",
	})
	res, err := v.Verify(context.Background(), "any", "test-nonce-1")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Verdict != VerdictOK {
		t.Errorf("verdict %s, want ok; reasons=%v", res.Verdict, res.Reasons)
	}
}

func TestVerify_RejectsNonceMismatch(t *testing.T) {
	v, _ := New(Config{
		Decoder:             stubDecoder(payloadOK()),
		ExpectedPackageName: "com.aidotvpn.client.app",
	})
	res, _ := v.Verify(context.Background(), "any", "different-nonce")
	if res.Verdict != VerdictFail {
		t.Errorf("expected fail on nonce mismatch")
	}
}

func TestVerify_RejectsWrongPackage(t *testing.T) {
	p := payloadOK()
	p.RequestDetails.RequestPackageName = "com.evil.spoof"
	v, _ := New(Config{
		Decoder:             stubDecoder(p),
		ExpectedPackageName: "com.aidotvpn.client.app",
	})
	res, _ := v.Verify(context.Background(), "any", "test-nonce-1")
	if res.Verdict != VerdictFail {
		t.Error("expected fail on package mismatch")
	}
}

func TestVerify_StrongIntegrityRequired(t *testing.T) {
	p := payloadOK()
	p.DeviceIntegrity.DeviceRecognitionVerdict = []string{"MEETS_DEVICE_INTEGRITY"}
	v, _ := New(Config{
		Decoder:             stubDecoder(p),
		ExpectedPackageName: "com.aidotvpn.client.app",
		MinDeviceIntegrity:  IntegrityStrong,
	})
	res, _ := v.Verify(context.Background(), "any", "test-nonce-1")
	if res.Verdict != VerdictFail {
		t.Errorf("device integrity %v should fail when STRONG required", p.DeviceIntegrity.DeviceRecognitionVerdict)
	}
}

func TestVerify_BasicIntegrityWarningOnSideload(t *testing.T) {
	p := payloadOK()
	p.AppIntegrity.AppRecognitionVerdict = "UNRECOGNIZED_VERSION"
	v, _ := New(Config{
		Decoder:             stubDecoder(p),
		ExpectedPackageName: "com.aidotvpn.client.app",
		AllowSideloaded:     true,
	})
	res, _ := v.Verify(context.Background(), "any", "test-nonce-1")
	if res.Verdict != VerdictWarning {
		t.Errorf("verdict %s, want warning", res.Verdict)
	}
}

func TestVerify_BasicIntegrityFailWhenSideloadDisallowed(t *testing.T) {
	p := payloadOK()
	p.AppIntegrity.AppRecognitionVerdict = "UNRECOGNIZED_VERSION"
	v, _ := New(Config{
		Decoder:             stubDecoder(p),
		ExpectedPackageName: "com.aidotvpn.client.app",
		AllowSideloaded:     false,
	})
	res, _ := v.Verify(context.Background(), "any", "test-nonce-1")
	if res.Verdict != VerdictFail {
		t.Errorf("verdict %s, want fail", res.Verdict)
	}
}

func TestVerify_DemoteToWarning_PreservesFail(t *testing.T) {
	p := payloadOK()
	p.AppIntegrity.AppRecognitionVerdict = "UNRECOGNIZED_VERSION"
	p.DeviceIntegrity.DeviceRecognitionVerdict = []string{} // FAILS
	v, _ := New(Config{
		Decoder:             stubDecoder(p),
		ExpectedPackageName: "com.aidotvpn.client.app",
		AllowSideloaded:     true,
	})
	res, _ := v.Verify(context.Background(), "any", "test-nonce-1")
	if res.Verdict != VerdictFail {
		t.Errorf("verdict %s, want fail (warning should not raise back to OK)", res.Verdict)
	}
}
