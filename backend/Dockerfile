FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOME=/home/aivuln
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

ARG APP_UID=1001
ARG APP_GID=1001

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid "${APP_GID}" aivuln \
    && useradd \
        --uid "${APP_UID}" \
        --gid "${APP_GID}" \
        --create-home \
        --home-dir /home/aivuln \
        --shell /usr/sbin/nologin \
        aivuln \
    && install -d \
        -o aivuln \
        -g aivuln \
        -m 0750 \
        /app \
        /ms-playwright

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install pyyaml

# Browser support for HTML-to-PDF report rendering
RUN python -m playwright install --with-deps chromium

RUN chown -R aivuln:aivuln /ms-playwright

COPY --chown=aivuln:aivuln app ./app

USER aivuln:aivuln

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
