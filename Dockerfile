FROM python:3.10

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY . .

# Hugging Face Spaces requires the app to listen on port 7860
ENV PORT=7860
EXPOSE 7860

CMD ["gunicorn", "-b", "0.0.0.0:7860", "--workers", "1", "--threads", "2", "--timeout", "120", "backend.app:app"]
