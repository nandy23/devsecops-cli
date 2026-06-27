package connector

import (
	"github.com/nandy23/devsecops-cli/internal/domain/port"
	"github.com/nandy23/devsecops-cli/internal/infra/config"
)

// Builtin constructs the set of enabled connectors from configuration. Secrets
// are resolved from the environment so tokens never live in committed files.
func Builtin(cfg config.Config) []port.Connector {
	var out []port.Connector

	if sq := cfg.Connectors.SonarQube; sq.Enabled {
		out = append(out, NewSonar(SonarConfig{
			URL:     sq.URL,
			Project: sq.Project,
			Token:   config.ResolveSecret(sq.Token),
		}))
	}

	if hb := cfg.Connectors.Harbor; hb.Enabled {
		out = append(out, NewHarbor(HarborConfig{
			URL:      hb.URL,
			Project:  hb.Project,
			Username: hb.Username,
			Secret:   config.ResolveSecret(hb.Secret),
		}))
	}

	if nx := cfg.Connectors.Nexus; nx.Enabled {
		out = append(out, NewNexus(NexusConfig{
			URL:         nx.URL,
			Application: nx.Application,
			Username:    nx.Username,
			Secret:      config.ResolveSecret(nx.Secret),
		}))
	}

	if vt := cfg.Connectors.Vault; vt.Enabled {
		out = append(out, NewVault(VaultConfig{
			URL:   vt.URL,
			Token: config.ResolveSecret(vt.Token),
		}))
	}

	if dt := cfg.Connectors.DependencyTrack; dt.Enabled {
		out = append(out, NewDTrack(DTrackConfig{
			URL:     dt.URL,
			Project: dt.Project,
			Version: dt.Version,
			APIKey:  config.ResolveSecret(dt.APIKey),
		}))
	}

	if xr := cfg.Connectors.Xray; xr.Enabled {
		out = append(out, NewXray(XrayConfig{
			URL:   xr.URL,
			Watch: xr.Watch,
			Token: config.ResolveSecret(xr.Token),
		}))
	}

	if dd := cfg.Connectors.DefectDojo; dd.Enabled {
		out = append(out, NewDefectDojo(DefectDojoConfig{
			URL:     dd.URL,
			Product: dd.Product,
			Token:   config.ResolveSecret(dd.Token),
		}))
	}

	if ky := cfg.Connectors.Kyverno; ky.Enabled {
		out = append(out, NewKyverno(KyvernoConfig{
			URL:       ky.URL,
			Token:     config.ResolveSecret(ky.Token),
			Namespace: ky.Namespace,
			Insecure:  ky.Insecure,
		}))
	}

	if fc := cfg.Connectors.Falco; fc.Enabled {
		out = append(out, NewFalco(FalcoConfig{
			URL:       fc.URL,
			Token:     config.ResolveSecret(fc.Token),
			Namespace: fc.Namespace,
			DaemonSet: fc.DaemonSet,
			Insecure:  fc.Insecure,
		}))
	}

	if rk := cfg.Connectors.Rekor; rk.Enabled {
		out = append(out, NewRekor(RekorConfig{
			URL:   rk.URL,
			Email: rk.Email,
			Hash:  rk.Hash,
		}))
	}

	if jk := cfg.Connectors.Jenkins; jk.Enabled {
		out = append(out, NewJenkins(JenkinsConfig{
			URL:      jk.URL,
			Job:      jk.Job,
			Username: jk.Username,
			Token:    config.ResolveSecret(jk.Token),
		}))
	}

	return out
}
