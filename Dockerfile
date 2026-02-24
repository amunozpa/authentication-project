# ── Imagen base ──────────────────────────────────────────────────────────────
FROM node:20-alpine

WORKDIR /app

# Herramientas de compilación necesarias para better-sqlite3 (addon nativo C++)
RUN apk add --no-cache python3 make g++

# ── Dependencias ──────────────────────────────────────────────────────────────
# Copiar solo los archivos de dependencias primero (cache de capas)
COPY package*.json ./
RUN npm ci

# Limpiar herramientas de compilación (reducir imagen final)
RUN apk del python3 make g++

# ── Código fuente ─────────────────────────────────────────────────────────────
COPY . .

# Directorio para la base de datos SQLite (montado como volumen)
RUN mkdir -p /data

# ── Usuario no-root (seguridad) ───────────────────────────────────────────────
RUN addgroup -S appgroup && adduser -S appuser -G appgroup && \
    chown -R appuser:appgroup /app /data
USER appuser

# ── Configuración ─────────────────────────────────────────────────────────────
EXPOSE 3000

# Health check interno (usa el endpoint /api/v1/health)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/v1/health || exit 1

# Ejecutar con tsx (sin paso de compilación — lab/desarrollo)
CMD ["npx", "tsx", "src/index.ts"]
