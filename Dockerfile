FROM alpine:latest
RUN apk update && apk upgrade && apk add py-pip
RUN mkdir -p /usr/Neo4Cyclone
WORKDIR /usr/Neo4Cyclone
COPY *.py .
COPY requirements.txt .
RUN pip3 install -r requirements.txt
RUN rm requirements.txt ingest_data_neo4j.py
EXPOSE 8080
ENTRYPOINT ["python"]
CMD ["main.py"]