package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nandy23/devsecops-cli/internal/domain/model"
	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// SSLyze imports SSLyze JSON reports (`sslyze --json_out=sslyze.json <target>`).
// It surfaces the high-signal transport-security problems: weak/legacy protocols
// still accepted, failed certificate validation, and well-known TLS
// vulnerabilities (Heartbleed, CCS injection, ROBOT). Category: dast — TLS
// posture is a property of the running endpoint. A parsed report credits DAST
// coverage even when nothing is wrong.
type SSLyze struct{}

func (SSLyze) Tool() string { return "sslyze" }

type sslyzeReport struct {
	ServerScanResults []struct {
		ServerLocation struct {
			Hostname string `json:"hostname"`
			Port     int    `json:"port"`
		} `json:"server_location"`
		ScanResult struct {
			SSL2       sslyzeCiphers `json:"ssl_2_0_cipher_suites"`
			SSL3       sslyzeCiphers `json:"ssl_3_0_cipher_suites"`
			TLS10      sslyzeCiphers `json:"tls_1_0_cipher_suites"`
			TLS11      sslyzeCiphers `json:"tls_1_1_cipher_suites"`
			Heartbleed struct {
				Result struct {
					Vulnerable bool `json:"is_vulnerable_to_heartbleed"`
				} `json:"result"`
			} `json:"heartbleed"`
			CCS struct {
				Result struct {
					Vulnerable bool `json:"is_vulnerable_to_ccs_injection"`
				} `json:"result"`
			} `json:"openssl_ccs_injection"`
			Robot struct {
				Result struct {
					RobotResult string `json:"robot_result"`
				} `json:"result"`
			} `json:"robot"`
			CertificateInfo struct {
				Result struct {
					Deployments []struct {
						PathValidation []struct {
							Successful bool `json:"was_validation_successful"`
						} `json:"path_validation_results"`
					} `json:"certificate_deployments"`
				} `json:"result"`
			} `json:"certificate_info"`
		} `json:"scan_result"`
	} `json:"server_scan_results"`
}

type sslyzeCiphers struct {
	Result struct {
		Accepted []struct {
			CipherSuite struct {
				Name string `json:"name"`
			} `json:"cipher_suite"`
		} `json:"accepted_cipher_suites"`
	} `json:"result"`
}

func (z SSLyze) Import(_ context.Context, fsys port.FileSystem) ([]model.ScanResult, error) {
	files := discover(fsys,
		[]string{"sslyze.json", "sslyze-report.json", "sslyze-results.json"},
		[]string{".sslyze.json"})

	var out []model.ScanResult
	for _, path := range files {
		data, err := read(fsys, path)
		if err != nil {
			continue
		}
		var rep sslyzeReport
		if err := json.Unmarshal(data, &rep); err != nil {
			continue
		}
		if rep.ServerScanResults == nil {
			continue // not an sslyze report
		}
		res := model.ScanResult{
			Tool:   z.Tool(),
			Source: path,
			Covers: []model.SecurityCategory{model.CatDAST},
		}
		for _, s := range rep.ServerScanResults {
			loc := fmt.Sprintf("%s:%d", s.ServerLocation.Hostname, s.ServerLocation.Port)
			r := s.ScanResult

			for proto, ciphers := range map[string]sslyzeCiphers{
				"SSL 2.0": r.SSL2, "SSL 3.0": r.SSL3, "TLS 1.0": r.TLS10, "TLS 1.1": r.TLS11,
			} {
				if len(ciphers.Result.Accepted) > 0 {
					sev := model.SevMedium
					if proto == "SSL 2.0" || proto == "SSL 3.0" {
						sev = model.SevHigh
					}
					res.Findings = append(res.Findings, finding(z.Tool(), path,
						model.CatDAST, sev, "legacy protocol accepted: "+proto, loc))
				}
			}
			if r.Heartbleed.Result.Vulnerable {
				res.Findings = append(res.Findings, finding(z.Tool(), path,
					model.CatDAST, model.SevCritical, "vulnerable to Heartbleed (CVE-2014-0160)", loc))
			}
			if r.CCS.Result.Vulnerable {
				res.Findings = append(res.Findings, finding(z.Tool(), path,
					model.CatDAST, model.SevHigh, "vulnerable to OpenSSL CCS injection (CVE-2014-0224)", loc))
			}
			if r.Robot.Result.RobotResult != "" && !isRobotSafe(r.Robot.Result.RobotResult) {
				res.Findings = append(res.Findings, finding(z.Tool(), path,
					model.CatDAST, model.SevHigh, "vulnerable to ROBOT attack ("+r.Robot.Result.RobotResult+")", loc))
			}
			certFailed := false
			for _, d := range r.CertificateInfo.Result.Deployments {
				for _, pv := range d.PathValidation {
					if !pv.Successful {
						certFailed = true
					}
				}
			}
			if certFailed {
				res.Findings = append(res.Findings, finding(z.Tool(), path,
					model.CatDAST, model.SevHigh, "certificate failed path validation", loc))
			}
		}
		out = append(out, res)
	}
	return out, nil
}

func isRobotSafe(result string) bool {
	// sslyze reports NOT_VULNERABLE_* when the server is safe.
	return strings.HasPrefix(result, "NOT_VULNERABLE")
}
