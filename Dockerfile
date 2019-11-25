FROM ubuntu:18.04

COPY . .

RUN apt-get update && apt-get install -y \
    python3-pip \
    tshark \
    && pip3 --no-cache-dir install -r requirements.txt

# CMD [ "python3" , "./src/recorder.py" ]