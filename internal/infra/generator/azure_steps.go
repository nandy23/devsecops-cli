package generator

import (
	"strings"
	"text/template"

	"github.com/nandy23/devsecops-cli/internal/domain/pipeline"
)

// AzureFuncs renders a full Azure DevOps pipeline with real, runnable stages.
func AzureFuncs() template.FuncMap {
	return template.FuncMap{"azureRender": azureRender}
}

func azureRender(spec pipeline.Spec) string {
	var b strings.Builder
	b.WriteString("trigger:\n  branches:\n    include:\n      - main\n\n")
	b.WriteString("pool:\n  vmImage: ubuntu-latest\n\n")
	b.WriteString("stages:\n")

	prev := ""
	for _, s := range spec.Stages {
		if s.Kind == pipeline.StageCheckout {
			continue
		}
		b.WriteString("  - stage: " + s.ID + "\n")
		b.WriteString("    displayName: " + s.Name + "\n")
		if prev != "" {
			b.WriteString("    dependsOn: [" + prev + "]\n")
		} else {
			b.WriteString("    dependsOn: []\n")
		}
		b.WriteString("    jobs:\n")

		if len(s.Tools) == 0 {
			writeAzureJob(&b, s.ID, langImage(spec.Lang), s.Name, structuralCmds(s.Kind, spec.Lang), false)
		} else {
			for _, tool := range s.Tools {
				img := toolImage(tool)
				if img == "" {
					img = langImage(spec.Lang)
				}
				writeAzureJob(&b, s.ID+"_"+tool, img, "Run "+tool, toolShell(tool, s.Kind), tool == "sonarqube")
			}
		}
		prev = s.ID
	}
	return b.String()
}

func writeAzureJob(b *strings.Builder, job, image, display string, script []string, sonarEnv bool) {
	b.WriteString("      - job: " + sanitizeAzureID(job) + "\n")
	b.WriteString("        container: " + image + "\n")
	b.WriteString("        steps:\n")
	b.WriteString("          - checkout: self\n")
	b.WriteString("          - script: |\n")
	for _, line := range script {
		b.WriteString("              " + line + "\n")
	}
	b.WriteString("            displayName: " + display + "\n")
	if sonarEnv {
		b.WriteString("            env:\n")
		b.WriteString("              SONAR_TOKEN: $(SONAR_TOKEN)\n")
		b.WriteString("              SONAR_HOST_URL: $(SONAR_HOST_URL)\n")
	}
}

// sanitizeAzureID makes a job identifier valid for Azure (letters, digits, _).
func sanitizeAzureID(s string) string {
	return strings.NewReplacer("-", "_", ".", "_").Replace(s)
}
