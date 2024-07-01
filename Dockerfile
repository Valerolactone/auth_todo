FROM python:3.12-slim

RUN pip install poetry

WORKDIR /app

COPY pyproject.toml poetry.lock ./

RUN apt-get update && apt-get install -y curl && apt-get clean
RUN poetry install

COPY . .

RUN chmod +x ./entrypoint.sh