import sqlite3
import json
import os

def extract_python_data():
    print("Starting optimized parsing...", flush=True)
    python_fids = set()
    python_files = {} # file_change_id -> (hash, filename)
    
    # Pass 1: Get python file IDs
    with open("data/cvefixes/CVEfixes.sqlite", "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i % 10000 == 0:
                print(f"Pass 1: Read {i} lines...", flush=True)
            if line.startswith("INSERT INTO file_change VALUES"):
                if "'Python'" in line:
                    try:
                        inner = line[line.find("(")+1:line.rfind(");")]
                        parts = inner.split("','")
                        if len(parts) >= 3:
                            fid = parts[0].strip().strip("'")
                            hsh = parts[1]
                            fname = parts[2]
                            python_fids.add(fid)
                            python_files[fid] = (hsh, fname)
                    except:
                        pass
            if line.startswith('CREATE TABLE IF NOT EXISTS "method_change"'):
                break
                
    print(f"Found {len(python_fids)} Python files.", flush=True)
    
    sql_inserts = [
        "CREATE TABLE method_change (col1 TEXT, file_change_id TEXT, col3 TEXT, col4 TEXT, col5 TEXT, col6 TEXT, col7 TEXT, before_change_body TEXT, after_change_body TEXT, col10 TEXT, col11 TEXT, col12 TEXT, col13 TEXT);"
    ]
    
    in_method_change = False
    with open("data/cvefixes/CVEfixes.sqlite", "r", encoding="utf-8", errors="ignore") as f:
        current_stmt = []
        in_insert = False
        
        for i, line in enumerate(f):
            if i % 10000 == 0:
                print(f"Pass 2: Read {i} lines...", flush=True)
            
            if line.startswith('CREATE TABLE IF NOT EXISTS "method_change"'):
                in_method_change = True
                continue
            if line.startswith('CREATE TABLE IF NOT EXISTS "cve"'):
                break
                
            if in_method_change:
                if line.startswith("INSERT INTO method_change VALUES("):
                    in_insert = True
                    current_stmt = [line]
                elif in_insert:
                    current_stmt.append(line)
                
                if in_insert and line.strip().endswith(");"):
                    # Complete statement
                    stmt = "".join(current_stmt)
                    in_insert = False
                    
                    # Check if it belongs to a python file
                    # File ID is the 2nd value. We can extract it by regex or simply finding quotes
                    try:
                        first_quote = stmt.find("'")
                        second_quote = stmt.find("'", first_quote+1)
                        third_quote = stmt.find("'", second_quote+1)
                        fourth_quote = stmt.find("'", third_quote+1)
                        f_id = stmt[third_quote+1:fourth_quote]
                        if f_id in python_fids:
                            sql_inserts.append(stmt)
                    except:
                        pass
                    
    print(f"Extracted {len(sql_inserts) - 1} Python method insert statements.")
    
    # Step 3: Load into SQLite and extract bodies
    print("Loading into memory DB...")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    
    script = "".join(sql_inserts)
    cursor.executescript(script)
    
    cursor.execute("SELECT * FROM method_change")
    rows = cursor.fetchall()
    
    out_path = "data/processed/python_functions.jsonl"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    
    saved = 0
    with open(out_path, "w", encoding="utf-8") as out:
        for row in rows:
            m_id = row[0]
            f_id = row[1]
            code = row[7] # before_change_body (8th col)
            is_before = row[12] # 13th col
            hsh, fname = python_files.get(f_id, ("unknown", "unknown"))
            
            if code and len(code.strip()) > 10:
                is_vuln = 1 if is_before == "True" or is_before == "1" else 0
                out.write(json.dumps({
                    "id": f"{'vuln' if is_vuln else 'fix'}_{m_id}",
                    "code": code,
                    "label": is_vuln,
                    "project": hsh,
                    "pair": f_id, # using file_change_id as pair grouping
                    "filename": fname
                }) + "\n")
                saved += 1
                
    print(f"Saved {saved} function records to {out_path}.")
    conn.close()

if __name__ == "__main__":
    extract_python_data()
