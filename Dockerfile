FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install httpx jinja2 --no-cache-dir

COPY monitor.py .
COPY templates/ templates/

CMD ["python", "monitor.py"]