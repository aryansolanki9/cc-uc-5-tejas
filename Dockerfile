FROM python:alpine3.7 

COPY . /NoQueue

WORKDIR /NoQueue

RUN pip install -r requirements.txt 
EXPOSE 5001 


CMD ["flask","run" ]