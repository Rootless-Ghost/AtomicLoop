FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN addgroup --system atomicloop && adduser --system --ingroup atomicloop atomicloop
USER atomicloop

EXPOSE 5011

# Note: DATABASE_URL should always be set in Docker deployments (PostgreSQL).
# SQLite is not recommended in containers — the database file is owned by root
# after COPY and is not writable by the atomicloop user without a named volume.
CMD ["gunicorn", "--bind", "0.0.0.0:5011", "--workers", "2", "--timeout", "120", "app:app"]
