FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY beta /app
RUN pip install --no-cache-dir -c constraints-tested.txt ".[postgres,aws,entra]"     && useradd --uid 65532 --create-home eda     && mkdir -p /data && chown eda:eda /data
USER 65532:65532
ENV EDA_DATABASE_URL=sqlite:////data/eda.db EDA_AUDIT_ANCHOR_PATH=/data/audit_anchors.jsonl
EXPOSE 8000
CMD ["uvicorn", "eda.api:app", "--host", "0.0.0.0", "--port", "8000"]
