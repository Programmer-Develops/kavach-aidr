import re
import json

def parse_sql_dump():
    print("Starting parse...")
    python_file_changes = set()
    python_commits = {}
    
    # We will need two passes or store everything?
    # Commits are before file_change (Line 8369 vs 16185). So we can store commit repos.
    # We need commit -> repo_url to associate project with method.
    commits = {}
    
    with open("data/cvefixes/CVEfixes.sqlite", "r", encoding="utf-8", errors="ignore") as f:
        current_table = None
        for i, line in enumerate(f):
            if line.startswith("CREATE TABLE"):
                current_table = line.split('"')[1] if '"' in line else line.split()[2]
                print(f"Reading table {current_table}...")
            elif line.startswith("INSERT INTO commits VALUES("):
                # INSERT INTO commits VALUES('hash', 'repo_url', ...)
                parts = line.split("','")
                if len(parts) >= 2:
                    hash_val = parts[0].split("VALUES('")[1]
                    repo_url = parts[1]
                    commits[hash_val] = repo_url
            elif line.startswith("INSERT INTO file_change VALUES("):
                # 'Python' is near the end. Let's just check if 'Python' is in the line.
                if "'Python'" in line:
                    # Extract file_change_id and hash
                    parts = line.split("','")
                    if len(parts) >= 2:
                        fc_id = parts[0].split("VALUES('")[1]
                        hash_val = parts[1]
                        # find filename which is usually the third column
                        filename = parts[2]
                        python_file_changes.add(fc_id)
                        python_commits[fc_id] = (commits.get(hash_val, "unknown"), filename)
            
            if current_table == "method_change":
                break

    print(f"Found {len(python_file_changes)} Python file changes.")
    
    # Pass 2: Extract method_change
    saved = 0
    with open("data/cvefixes/CVEfixes.sqlite", "r", encoding="utf-8", errors="ignore") as f, \\
         open("data/processed/python_functions.jsonl", "w", encoding="utf-8") as out:
        
        in_method_change = False
        for line in f:
            if line.startswith("CREATE TABLE IF NOT EXISTS \\"method_change\\""):
                in_method_change = True
                continue
            if line.startswith("CREATE TABLE IF NOT EXISTS \\"cve\\""):
                break
                
            if in_method_change and line.startswith("INSERT INTO method_change VALUES("):
                # The line might have replace('...'). It's tricky to parse SQL insert.
                # But we know file_change_id is the second value.
                # INSERT INTO method_change VALUES('method_id','file_id',...
                try:
                    prefix = line[:500] # get enough to see IDs
                    parts = prefix.split("','")
                    if len(parts) >= 2:
                        m_id = parts[0].split("VALUES('")[1]
                        fc_id = parts[1]
                        if fc_id in python_file_changes:
                            # We need to extract before_change_body and after_change_body.
                            # They are the 7th and 8th columns. 
                            # Since there might be internal quotes, let's just use regex.
                            # Usually before_change_body is before after_change_body.
                            # But wait, replace('...') is used. 
                            # Actually, a much safer way is to use SQLite memory DB just for method_change?
                            # No, memory DB would need the schema.
                            pass
                except Exception as e:
                    pass

if __name__ == "__main__":
    parse_sql_dump()
