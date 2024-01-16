FROM python:3.9

WORKDIR /app

COPY Pipfile Pipfile.lock /app/

RUN pip install pipenv && pipenv install --dev

COPY . /app

ENV PATH="/app/.venv/bin:$PATH"

CMD ["pipenv", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80", "--reload"]
