FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vnc_bot.py .
COPY d3des.py .

CMD ["python", "vnc_bot.py"]
