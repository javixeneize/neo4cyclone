import sbom_reader
from config import driver


def ingest_project(project):
    r = driver.execute_query('''
      MATCH (n)
      where n.project_name = $project
      return n
             ''', project=project.get('name'))
    if len(r.records) == 0:
        driver.execute_query('''
        MERGE (n:project {project_name: $project, timestamp: $timestamp, urn: $urn, dependencies: $dependencies})
        SET n.caption = $project
        RETURN n
        ''', project=project.get('name'), timestamp=project.get('timestamp'), urn=project.get('urn'),
                             dependencies=project.get('dependencies'))
        return project.get('name')


def ingest_dependencies(dependencies):
    deps_added = 0
    for dependency in dependencies:
        r = driver.execute_query('''
          MATCH (d)
          where d.purl = $purl  AND d.dependency = $dependency
          return d
                 ''', purl=dependency.get('purl'), dependency=dependency.get('dependency'))
        if len(r.records) == 0:
            driver.execute_query('''
               MERGE (d:dependency {purl: $purl, dependency: $dependency})
                SET d.caption = $dependency
                RETURN d
               ''', purl=dependency.get('purl'), dependency=dependency.get('dependency'))
            deps_added += 1
    return deps_added


def ingest_vulns(vulns_list):
    vulns_added = 0
    for vuln in vulns_list:
        r = driver.execute_query('''
          MATCH (v)
          where v.id = $id AND v.id = $id
          return v
                 ''', id=vuln.get('id'))
        if len(r.records) == 0:
            driver.execute_query('''
            MERGE (v:vulnerability {id: $id, score: $score, libraries: $libraries})
            SET v.caption = $id
            RETURN v
            ''', id=vuln.get('id'), score=vuln.get('score'), libraries=vuln.get('libraries'))
            vulns_added += 1
        else:
            for record in r.records:
                if record.data().get('v').get('score') != vuln.get('score'):
                    driver.execute_query('''
                                MATCH (v:vulnerability {id: $id})
                                SET v.score = $score
                                RETURN v
                                ''', id=vuln.get('id'), score=vuln.get('score'))
                for library in vuln.get('libraries'):
                    if library not in record.data().get('v').get('libraries'):
                        newlist = record.data().get('v').get('libraries')
                        newlist.append(library)
                        driver.execute_query('''
                                    MATCH (v:vulnerability {id: $id})
                                    SET v.libraries = $libraries
                                    RETURN v
                                    ''', id=vuln.get('id'), libraries=newlist)
    return vulns_added


def create_project_relations():
    driver.execute_query('''
    MATCH (d:dependency), (p:project)
    WHERE d.purl IN  p.dependencies
    MERGE (p)-[:USES]->(d)
    ''')


def create_vuln_relations():
    driver.execute_query('''   MATCH (d:dependency), (v:vulnerability)
    WHERE d.purl IN  v.libraries

    MERGE(d)-[:VULNERABLE_TO]->(v)
    ''')


def ingest_data(project, data):
    project_data, deps, vulns = sbom_reader.get_sbom_data(project, data)
    project_name = ingest_project(project_data)
    dep_number = 0
    vuln_number = 0
    if project_name:
        dep_number = ingest_dependencies(deps)
        vuln_number = ingest_vulns(vulns)
        create_project_relations()
        create_vuln_relations()
    driver.close()
    return project_name, dep_number, vuln_number
