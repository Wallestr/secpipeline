FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt pyproject.toml ./
COPY secpipeline ./secpipeline
COPY knowledge ./knowledge
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir -e .

EXPOSE 8088
CMD ["python", "-m", "secpipeline", "serve"]
