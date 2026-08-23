# ─────────────────────────────────────────────────────────────────────────────
#  AutoPentestX — Multi-stage Docker image
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

LABEL stage=builder

# Install build-time tools for compiled wheels.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a virtual environment so we can copy it cleanly in stage 2.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install optional Python dependencies.
# These are all optional in AutoPentestX (modules fall back to pure stdlib),
# but including them in the image gives full functionality.
RUN pip install --no-cache-dir \
        cryptography \
        flask \
        psutil \
        requests


# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"

# Copy the pre-built virtual environment from the builder stage.
COPY --from=builder /opt/venv /opt/venv

# Create a non-root user for runtime security.
RUN useradd --create-home --shell /bin/bash appuser

# Copy the application source.
COPY . /app

# Fix ownership so appuser can write to the working directories.
RUN chown -R appuser:appuser /app

WORKDIR /app

# Switch to the non-root user.
USER appuser

# ── Ports ─────────────────────────────────────────────────────────────────────
# 8443 — C2 HTTPS listener (c2_server.py)
# 5000 — Dashboard web interface (dashboard/app.py)
EXPOSE 8443 5000

# ── Default command ───────────────────────────────────────────────────────────
CMD ["python", "main.py", "--help"]
