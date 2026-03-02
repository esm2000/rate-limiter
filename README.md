# rate-limiter
This repository contains the incomplete implementation of a low-latency, distributed rate-limiter with high tolerance. This is a work in progress.

# Get Started
Run `docker compose up --build` on first run or after any dependency changes to ensure a clean image is built.

Subsequent runs can use `docker compose up`.

To pick up database schema changes, the existing volume must be destroyed first:
```
docker compose down -v && docker compose up --build
```

# Documentation
To be written...

# References
* docker-compose setup - https://geshan.com.np/blog/2022/01/redis-docker/