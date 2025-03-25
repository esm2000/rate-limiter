import os
import psycopg2

PG_CREDENTIALS = (
    'host=database '
    'port=5432 '
    'dbname=postgres '
    f'user={os.getenv("POSTGRES_USER")} '
    f'password={os.getenv("POSTGRES_PASSWORD")}'
)

def get_data_from_database(query, params=()):
    with psycopg2.connect(PG_CREDENTIALS) as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        entry = cur.fetchall()
        return entry
    
def alter_database(query, params=()):
    with psycopg2.connect(PG_CREDENTIALS) as conn:
        cur = conn.cursor()
        cur.execute(query, params)