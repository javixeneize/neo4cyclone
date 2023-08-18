import json

FORMAT='CycloneDX'
VERSION='1.4'

def get_sbom_data(project_name, file):
    with open (file) as f:
        data = json.loads(f.read())
    if data.get('bomFormat') != FORMAT or data.get('specVersion') !=VERSION:
        print ("Format not supported")
        exit(2)
    project =  {'name': project_name,
                'timestamp': data.get('metadata').get('timestamp'),
                'urn': data.get('serialNumber'),
                'dependencies': [component.get('purl') for component in data.get('components')]
                }
    dependencies  = get_dependencies(data.get('components'))
    vulnerabilities = get_vulnerabilities(data.get('vulnerabilities'))
    return project, dependencies, vulnerabilities


def get_dependencies( components):
    dependencies = []
    for component in components:
        dependency = component.get('name') + '@' + component.get('version')
        if component.get('group'):
            dependency = component.get('group') + dependency
            dep = {'purl': component.get('purl'),'dependency': dependency}
        dependencies.append(dep)
    return dependencies

def get_vulnerabilities( vuln_data):
    vulnerabilities = []
    for vuln in vuln_data:
        vulnerability = {'libraries': [item.get('ref') for item in vuln.get('affects')],
                        'id': vuln.get('id'),
                        'score': vuln.get('ratings')[0].get('score')}
        vulnerabilities.append(vulnerability)
    return vulnerabilities

# get_sbom_data('test', 'sbom.json')