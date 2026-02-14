FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY src/ src/
COPY config/ config/
COPY alembic.ini .
COPY alembic/ alembic/

RUN mkdir -p data

EXPOSE 8000

CMD ["uvicorn", "zuultimate.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
