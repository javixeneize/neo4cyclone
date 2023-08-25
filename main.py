import ingest_data_neo4j_flask
from flask import Flask, request, jsonify
import json

app = Flask(__name__)

@app.route('/', methods=['POST'])
def upload_file():
    file = request.files['file']
    project = request.form['project']
    try:
        file_contents = json.loads(file.read())
        project, deps, vulns = ingest_data_neo4j_flask.run_cli_scan(project, file_contents)
        return jsonify({"Name": project, "New dependencies added": deps, "New vulnerabilities added": vulns})
    except json.decoder.JSONDecodeError:
        return jsonify({"Error": "The file is not a valid JSON"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)

