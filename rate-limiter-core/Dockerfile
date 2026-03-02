# syntax=docker/dockerfile:1

FROM python:3.12.10-bullseye AS base

WORKDIR /rate-limiter-core

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

FROM base AS test
RUN python3 -m pytest tests/unit/ -v

FROM test AS production
CMD [ "python3", "app.py"]
