# Dockerfile para sslscan

# Estágio de build
FROM golang:1.21-alpine AS builder

# Instalar dependências necessárias
RUN apk add --no-cache git ca-certificates tzdata

# Definir diretório de trabalho
WORKDIR /app

# Copiar arquivos de dependências
COPY go.mod go.sum ./

# Baixar dependências
RUN go mod download

# Copiar código fonte
COPY . .

# Compilar o aplicativo
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o sslscan cmd/main.go

# Estágio final
FROM scratch

# Copiar certificados CA e timezone
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copiar o binário compilado
COPY --from=builder /app/sslscan /sslscan

# Definir variáveis de ambiente
ENV TZ=UTC

# Expor porta (opcional, para documentação)
EXPOSE 443

# Definir o comando padrão
ENTRYPOINT ["/sslscan"]

# Argumentos padrão
CMD ["--help"]
