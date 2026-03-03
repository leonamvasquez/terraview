# Docker

## Imagem oficial

```bash
docker pull ghcr.io/leonamvasquez/terraview:latest
```

## Uso básico

```bash
docker run --rm -v $(pwd):/workspace -w /workspace ghcr.io/leonamvasquez/terraview scan checkov
```

## Saída SARIF com arquivo salvo

```bash
docker run --rm -v $(pwd):/workspace -w /workspace \
  ghcr.io/leonamvasquez/terraview scan checkov -f sarif -o /workspace/reports
```

## Com IA (API key via variável de ambiente)

```bash
docker run --rm \
  -v $(pwd):/workspace -w /workspace \
  -e GEMINI_API_KEY="$GEMINI_API_KEY" \
  ghcr.io/leonamvasquez/terraview scan checkov --provider gemini
```

## Com Ollama (rede host)

```bash
docker run --rm \
  -v $(pwd):/workspace -w /workspace \
  --network host \
  ghcr.io/leonamvasquez/terraview scan checkov --provider ollama
```

## Build local da imagem

```bash
# No diretório do projeto
make docker-build

# Ou diretamente
docker build -t terraview .
```

## Docker Compose

```yaml
services:
  terraview:
    image: ghcr.io/leonamvasquez/terraview:latest
    volumes:
      - .:/workspace
    working_dir: /workspace
    command: scan checkov -f json -o /workspace/reports
```
