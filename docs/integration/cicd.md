# Integração CI/CD

O terraview foi projetado para integração nativa com pipelines de CI/CD, oferecendo:

- **Exit codes semânticos** — `0` (ok), `1` (HIGH), `2` (CRITICAL)
- **Saída SARIF** — para GitHub Security tab
- **Saída JSON/Markdown** — para artefatos e comentários em PRs

---

## GitHub Actions

```yaml
name: Terraform Security Scan
on:
  pull_request:
    paths: ['**.tf']

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Install terraview
        run: curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

      - name: Security scan
        run: terraview scan checkov -f sarif -o ./reports

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/review.sarif.json

      - name: Comment on PR
        if: always()
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: reports/review.md
```

### Com IA na pipeline

```yaml
      - name: Security scan with AI
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
        run: terraview scan checkov --provider gemini -f sarif -o ./reports
```

### Modo estrito

```yaml
      - name: Security scan (strict)
        run: terraview scan checkov --strict -f sarif -o ./reports
        # HIGH findings also return exit code 2 (block merge)
```

---

## GitLab CI

```yaml
terraform-scan:
  stage: validate
  script:
    - curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
    - terraview scan checkov -f json -o ./reports
  artifacts:
    paths: [reports/review.json, reports/review.md]
    when: always
```

---

## Azure DevOps

```yaml
- task: Bash@3
  displayName: 'Install terraview'
  inputs:
    targetType: 'inline'
    script: |
      curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

- task: Bash@3
  displayName: 'Security scan'
  inputs:
    targetType: 'inline'
    script: |
      terraview scan checkov -f sarif -o $(Build.ArtifactStagingDirectory)/reports

- task: PublishBuildArtifacts@1
  condition: always()
  inputs:
    pathToPublish: '$(Build.ArtifactStagingDirectory)/reports'
    artifactName: 'security-scan'
```

---

## Exit Codes para CI

| Código | Significado | Ação recomendada |
|--------|-------------|------------------|
| `0`    | Sem issues ou apenas MEDIUM/LOW/INFO | Merge permitido |
| `1`    | Findings HIGH | Warning, considerar revisão |
| `2`    | Findings CRITICAL (ou HIGH com `--strict`) | Bloquear merge |

!!! tip "Dica"
    Use `--strict` para bloquear PRs com findings HIGH ou CRITICAL. Sem `--strict`, apenas CRITICAL retorna exit code 2.
