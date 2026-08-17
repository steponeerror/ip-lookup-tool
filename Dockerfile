# syntax=docker/dockerfile:1

FROM node:22-alpine AS frontend
WORKDIR /build
ARG NPM_REGISTRY=""
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci ${NPM_REGISTRY:+--registry $NPM_REGISTRY}
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 IP_RADAR_DATA_DIR=/app/data
WORKDIR /app
ARG PIP_INDEX_URL=""
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt ${PIP_INDEX_URL:+-i $PIP_INDEX_URL}
COPY backend/ ./backend/
COPY --from=frontend /build/dist ./frontend/dist
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
