FROM python:3.12-slim

WORKDIR /app
ENV PYTHONPATH=/app

COPY apps/demo-control-ui/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY shared /app/shared
COPY apps/demo-control-ui/app /app/app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

