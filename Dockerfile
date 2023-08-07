FROM python:3.11-slim

COPY . /usr/src/app
WORKDIR /usr/src/app
ENV PYTHONPATH=${PYTHONPATH}:${PWD} 
RUN pip install --upgrade pip
RUN pip3 install poetry
RUN poetry config virtualenvs.create false
RUN poetry install  --no-dev -vvv
RUN apt update
RUN playwright install --with-deps chromium

