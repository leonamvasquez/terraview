# Security Policy

## Versões suportadas

| Versão   | Suporte de segurança |
|----------|----------------------|
| `latest` | ✅ Ativa             |
| `< latest - 1 minor` | ⚠️ Apenas críticos |
| Demais   | ❌ Sem suporte       |

## Reportar uma vulnerabilidade

**Não abra uma issue pública para vulnerabilidades de segurança.**

### Canal preferido

Envie um e-mail para: **security@leonamvasquez.dev**

Ou use o [GitHub Private Security Advisories](https://github.com/leonamvasquez/terraview/security/advisories/new).

### O que incluir no report

Por favor, forneça o máximo possível de informações:

- Descrição clara da vulnerabilidade
- Passos para reproduzir
- Impacto potencial (confidencialidade, integridade, disponibilidade)
- Versão do terraview afetada (`terraview version`)
- Sistema operacional e arquitetura

### SLA de resposta

| Prazo       | Ação                                            |
|-------------|-------------------------------------------------|
| 48h         | Confirmação de recebimento                      |
| 7 dias      | Avaliação de severidade e plano de resposta     |
| 30 dias     | Correção publicada (se confirmada crítica/alta) |
| 90 dias     | Divulgação pública (coordenada com o reporter)  |

### Supply chain

Este projeto implementa defesas de supply chain:

- **SBOM** (CycloneDX) publicado em cada release
- **Assinaturas cosign** (keyless, via OIDC) em binários e imagem Docker
- **SLSA Build Provenance** (nível 2) via GitHub Actions
- **CVE scanning** contínuo: govulncheck + OSV Scanner (semanal)
- **Imagem Docker** escaneada com Docker Scout antes de cada release

Os artefatos de provenance e assinaturas podem ser verificados com:

```bash
# Verificar assinatura do binário
cosign verify-blob terraview-linux-amd64.tar.gz \
  --signature terraview-linux-amd64.tar.gz.sig \
  --certificate terraview-linux-amd64.tar.gz.pem \
  --certificate-identity-regexp "https://github.com/leonamvasquez/terraview" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verificar provenance da imagem
cosign verify-attestation ghcr.io/leonamvasquez/terraview:latest \
  --type slsaprovenance \
  --certificate-identity-regexp "https://github.com/leonamvasquez/terraview" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Reconhecimento

Agradecemos a todos os pesquisadores que reportam vulnerabilidades de forma responsável.
Os reporters serão creditados no CHANGELOG e nas release notes, a menos que solicitem anonimato.
