FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/app
RUN useradd --system --uid 10001 --create-home appuser
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY integrations ./integrations
COPY socksio ./socksio
COPY tests ./tests
USER appuser
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=3)"
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8787","--proxy-headers","--forwarded-allow-ips=*"]
