FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
# Use a patched installer at build time; the running service does not need pip.
RUN python -m pip install --no-cache-dir --upgrade "pip>=26.2.1" \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && python -m pip uninstall --yes pip

COPY tiger_eye/ tiger_eye/

CMD ["python", "-m", "tiger_eye.main"]
