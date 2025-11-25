FROM python:3.11-slim

# Install Hydra and dependencies
RUN apt-get update && apt-get install -y \
    hydra \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy bot code
COPY vnc_bot.py .

# Copy data files (you'll upload these)
# COPY ips.txt .
# COPY passwords.txt .

# Run the bot
CMD ["python", "vnc_bot.py"]
