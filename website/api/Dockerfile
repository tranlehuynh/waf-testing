FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py sinks.py auth.py ./

EXPOSE 5000

# 4 workers handle GoTestWAF's parallel requests comfortably.
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
