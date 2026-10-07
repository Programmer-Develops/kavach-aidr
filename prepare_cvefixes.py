import sqlite3
import json
import os
from pathlib import Path

DB_PATH = "data/cvefixes/CVEfixes.sqlite"
OUT_PATH = "data/processed/python_functions.jsonl"

def inspect_schema(cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print("Tables:", [t[0] for t in tables])
    for t in tables:
        name = t[0]
        cursor.execute(f"PRAGMA table_info({name});")
        print(f"\\nTable: {name}")
        for col in cursor.fetchall():
            print(f"  {col[1]} ({col[2]})")

def extract_python_methods():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if this is the expected schema
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='method_change';")
    if not cursor.fetchone():
        print("Schema not standard CVEfixes sqlite. Inspecting:")
        inspect_schema(cursor)
        return

    # Extract vulnerable and fixed Python methods
    query = '''
    SELECT 
        m.method_change_id, 
        m.before_change_body, 
        m.after_change_body,
        f.filename,
        c.repo_url,
        f.programming_language
    FROM method_change m
    JOIN file_change f ON m.file_change_id = f.file_change_id
    JOIN commits c ON f.hash = c.hash
    WHERE f.programming_language = 'Python'
    '''
    
    cursor.execute(query)
    rows = cursor.fetchall()
    
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    
    saved = 0
    with open(OUT_PATH, 'w', encoding='utf-8') as f_out:
        for row in rows:
            mid, before, after, filename, repo, lang = row
            
            # Vulnerable version (before)
            if before and len(before.strip()) > 10:
                rec_vuln = {
                    "id": f"vuln_{mid}",
                    "code": before,
                    "label": 1,
                    "project": repo,
                    "pair": str(mid),
                    "filename": filename
                }
                f_out.write(json.dumps(rec_vuln) + "\\n")
                saved += 1
                
            # Fixed version (after)
            if after and len(after.strip()) > 10:
                rec_fix = {
                    "id": f"fix_{mid}",
                    "code": after,
                    "label": 0,
                    "project": repo,
                    "pair": str(mid),
                    "filename": filename
                }
                f_out.write(json.dumps(rec_fix) + "\\n")
                saved += 1

    print(f"Extracted {saved} Python function samples to {OUT_PATH}")
    conn.close()

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print(f"DB not found at {DB_PATH}")
    else:
        extract_python_methods()
