# ==========================================
# Stage 1: Build Frontend UI
# ==========================================
FROM node:22-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ==========================================
# Stage 2: Python Backend & Relay Server
# ==========================================
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RELAY_HOST=127.0.0.1 \
    RELAY_PORT=9999 \
    PORT=8000

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m spacy download en_core_web_sm

# Copy application source
COPY crypto/ ./crypto/
COPY utils/ ./utils/
COPY server/ ./server/
COPY client/ ./client/
COPY bridge/ ./bridge/
COPY demos/ ./demos/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Copy built frontend assets from stage 1
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

EXPOSE 8000 9999

ENTRYPOINT ["/app/entrypoint.sh"]
