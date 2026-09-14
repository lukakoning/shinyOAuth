FROM python:3.12.12-slim@sha256:f3fa41d74a768c2fce8016b98c191ae8c1bacd8f1152870a3f9f87d350920b7c
RUN python -m pip install --no-cache-dir cryptography==46.0.5 cffi==2.1.1 pycparser==3.0
WORKDIR /fixture
COPY server.py /fixture/server.py
ENTRYPOINT ["python", "/fixture/server.py"]
