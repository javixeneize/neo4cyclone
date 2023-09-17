FORMAT = 'CycloneDX'


def get_sbom_data(project_name, data):
    if data.get('bomFormat') != FORMAT:
        print("Format not supported")
        exit(2)
    project = {'name': project_name,
               'timestamp': data.get('metadata').get('timestamp'),
               'urn': data.get('serialNumber'),
               'dependencies': [component.get('bom-ref') for component in data.get('components') if
                                component.get('type') == 'library']
               }
    dependencies = get_dependencies(data.get('components'))
    if data.get('vulnerabilities'):
        vulnerabilities = get_vulnerabilities(data.get('vulnerabilities'))
    else:
        vulnerabilities = []
    return project, dependencies, vulnerabilities


def get_dependencies(components):
    dependencies = []
    for component in components:
        if component.get('type') == 'library':
            dependency = component.get('name') + '@' + component.get('version')
            if component.get('group'):
                dependency = component.get('group') + dependency
            dep = {'ref': component.get('bom-ref'), 'dependency': dependency}
            dependencies.append(dep)
    return dependencies


def get_vulnerabilities(vuln_data):
    vulnerabilities = []
    for vuln in vuln_data:
        vulnerability = {'libraries': [item.get('ref') for item in vuln.get('affects')],
                         'id': vuln.get('id'),
                         'score': vuln.get('ratings')[0].get('score')}
        vulnerabilities.append(vulnerability)
    return vulnerabilities
