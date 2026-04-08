FROM python:3.12-slim

WORKDIR /app
ENV PYTHONPATH=/app

COPY apps/normalizer/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY shared /app/shared
COPY infra /app/infra
COPY apps/normalizer/app /app/app
COPY apps/normalizer/examples /app/examples

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

