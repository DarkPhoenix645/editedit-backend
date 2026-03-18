FROM python:3.11

WORKDIR /app

RUN pip install uv

COPY ../../app/pyproject.toml ../../app/uv.lock* ./
RUN uv sync --no-dev --frozen

COPY ../../app ./app

CMD ["sh", "-c", "uv run uvicorn app.main:app --host ${HOST:-0.0.0.0} --port ${PORT:-8000}"]