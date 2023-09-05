import os
from neo4j import GraphDatabase

driver = GraphDatabase.driver(os.environ.get('NEO4J_DB'),
                              auth=(os.environ.get('NEO4J_USER'), os.environ.get('NEO4J_PWD')))
