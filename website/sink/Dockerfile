FROM python:3.12-slim

# iputils-ping gives the shell-injection sink a real `ping` base command to break out of;
# everything else (id, cat, ls, uname, getent, /bin/sh) is already in the base image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sink_app.py seed.py ./

EXPOSE 5001

# --preload seeds the fake DB/filesystem once in the master before forking workers.
# 4 workers keep up with GoTestWAF's parallelism; each payload is time- and rlimit-bounded.
CMD ["gunicorn", "--preload", "-w", "4", "-b", "0.0.0.0:5001", "sink_app:app"]
