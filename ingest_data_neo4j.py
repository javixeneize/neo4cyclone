from neo4j import GraphDatabase
import os
import click
import sbom_reader



def ingest_project(project): # todo verificar si el proyecto existe ya
    result = driver.execute_query('''
    MERGE (n:project {project_name: $project, timestamp: $timestamp, urn: $urn, dependencies: $dependencies})
    SET n.caption = $project
    RETURN n
    ''', project=project.get('name'), timestamp=project.get('timestamp'), urn=project.get('urn'),
           dependencies=project.get('dependencies'))
    print ("project {} added".format(project.get('name')))


def ingest_dependencies(dependencies):
    deps_added = 0
    for dependency in dependencies:
        r = driver.execute_query('''
          MATCH (d) 
          where d.purl = $purl  AND d.dependency = $dependency
          return d
                 ''', purl=dependency.get('purl'), dependency=dependency.get('dependency'))
        if len(r.records) == 0:
            result = driver.execute_query('''
               MERGE (d:dependency {purl: $purl, dependency: $dependency})
                SET d.caption = $dependency
                RETURN d
               ''', purl=dependency.get('purl'), dependency=dependency.get('dependency'))
            deps_added+=1
    print("{} dependencies added".format(deps_added))


def ingest_vulns(vulns_list): # todo ver que hacer cuando una vulnerabilidad exista, pero afecte a una libreria nueva
    vulns_added = 0
    for vuln in vulns_list:
        r = driver.execute_query('''
          MATCH (v) 
          where v.id = $id
          return v
                 ''', id=vuln.get('id'))
        if len(r.records) == 0: # si la vuln no existe en la bd
            result = driver.execute_query('''
            MERGE (v:vulnerability {id: $id, score: $score, libraries: $libraries})
            SET v.caption = $id
            RETURN v            
            ''', id=vuln.get('id'), score=vuln.get('score'), libraries=vuln.get('libraries'))
            vulns_added+=1
        else: # si existe, ver si afecta a alguna libreria nueva
            for record in r.records:
                for library in vuln.get('libraries'):
                    # ver si ha cambiado el score
                    if library not in record.data().get('v').get('libraries'):
                        print ('new library affected') ## ADD NEW LIBRARY!
    print("{} vulnerabilities added".format(vulns_added))


def create_project_relations():
    r = driver.execute_query('''
    MATCH (d:dependency), (p:project)
    WHERE d.purl IN  p.dependencies
    MERGE (p)-[:USES]->(d)
    ''')

def create_vuln_relations():
    driver.execute_query('''   MATCH (d:dependency), (v:vulnerability)
    WHERE d.purl IN  v.libraries

    MERGE(d)-[:VULNERABLE_TO]->(v)
    ''')

@click.command()
@click.argument('project', required=True)
@click.argument('file', required=False)
def run_cli_scan(project, file):
    if not file:
        file= 'sbom.json'
    project_data, deps, vulns = sbom_reader.get_sbom_data(project, file)
    ingest_project(project_data)
    ingest_dependencies(deps)
    ingest_vulns(vulns)
    create_project_relations()
    create_vuln_relations()
    print("Data successfully ingested in Neo4J")



if __name__ == "__main__":
    driver = GraphDatabase.driver(os.environ.get('NEO4J_DB'),
                                  auth=(os.environ.get('NEO4J_USER'), os.environ.get('NEO4J_PWD')))
    # run_cli_scan()
    run_cli_scan(['test'])
    driver.close()


