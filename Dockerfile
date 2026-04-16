FROM python:3.11-slim

LABEL maintainer="Forensic Security Team"
LABEL version="2.0-Enterprise"
LABEL description="Forensic Log Analyzer Container Image"

# Configurações de performance e ambiente
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Hardening basico: atualizar bibliotecas system
RUN apt-get update && apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Hardening: Adicionar usuário sem permissões de root
RUN groupadd -r forensic && useradd -r -g forensic forensic

WORKDIR /app

# Adicionar scripts e binarios do projeto
COPY forensic_analyzer.py ./
COPY dashboard/ ./dashboard/

# Criar diretorios necessarios de uso dinamico (outputs e inputs) e acertar permissões
RUN mkdir -p /logs /app/forensic_output && \
    chown -R forensic:forensic /app /logs

# Mudar contexto de execução para o novo usuário
USER forensic

# Ponto de acesso do container amarrando o script python
ENTRYPOINT ["python", "/app/forensic_analyzer.py"]

# Default command for standalone usage vs analytics server
# Uso com WebServer Habilitado seria: CMD ["/logs/target.log", "--serve", "--port", "8080"]
CMD ["--help"]
