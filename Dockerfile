FROM python:3.11-slim

USER root

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

ENV DATABASE_URL="postgresql://admin:password123@db:5432/myapp"
ENV SECRET_KEY="hardcoded-secret-key-123"
ENV DEBUG=True

CMD ["python", "app.py"]