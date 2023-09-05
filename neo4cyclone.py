import ingest_data_neo4j
from flask import Flask, request, jsonify
import json

app = Flask(__name__)


@app.route('/', methods=['POST'])
def upload_file():
    file = request.files['file']
    project = request.form['project']
    try:
        file_contents = json.loads(file.read())
        project, deps, vulns = ingest_data_neo4j.ingest_data(project, file_contents)
        if project:
            return jsonify({"Name": project, "New dependencies added": deps, "New vulnerabilities added": vulns})
        else:
            return jsonify({"Error": "Project already exists"})
    except (json.decoder.JSONDecodeError, FileNotFoundError):
        return jsonify({"Error": "The file is not a valid JSON or it does not exist"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
