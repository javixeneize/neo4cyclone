import json
import click
import ingest_data_neo4j


@click.command()
@click.argument('project', required=True)
@click.argument('file', required=True)
def run_cli_scan(project, file):
    try:
        with open(file) as f:
            data = json.loads(f.read())
        project, deps, vulns = ingest_data_neo4j.ingest_data(project, data)
        if project:
            print({"Name": project, "New dependencies added": deps, "New vulnerabilities added": vulns})
        else:
            print({"Error": "Project already exists"})

    except (json.decoder.JSONDecodeError, FileNotFoundError):
        print({"Error": "The file is not a valid JSON or it does not exist"})


if __name__ == "__main__":
    project, deps, vulns = run_cli_scan()
