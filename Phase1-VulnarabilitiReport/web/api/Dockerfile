# Build context: Phase1-VulnarabilitiReport/
FROM python:3.11-slim

WORKDIR /app

# Install breakbot package (scan engine)
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[llm,viz]"

# Install API server dependencies
COPY web/api/requirements.txt ./web/api/requirements.txt
RUN pip install --no-cache-dir -r web/api/requirements.txt

COPY web/api ./web/api
COPY web/lib ./web/lib

RUN mkdir -p /app/scans

EXPOSE 8000

CMD ["uvicorn", "web.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
