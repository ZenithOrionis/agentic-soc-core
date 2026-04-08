FROM python:3.12-slim

WORKDIR /tool
COPY tools/demo-attack-runner/attack_runner.py /tool/attack_runner.py

ENTRYPOINT ["python", "/tool/attack_runner.py"]
CMD ["list"]

