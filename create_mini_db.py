import sqlite3
import os

def create_mini_db():
    print("Extracting subset of SQL dump...")
    sql_lines = []
    
    with open("data/cvefixes/CVEfixes.sqlite", "r", encoding="utf-8", errors="ignore") as f:
        # We need lines from PRAGMA up to end of method_change
        for i, line in enumerate(f):
            if i < 143777: # up to cve table
                sql_lines.append(line)
            else:
                break
                
    print(f"Extracted {len(sql_lines)} lines. Saving to mini.sql")
    with open("data/cvefixes/mini.sql", "w", encoding="utf-8") as f:
        f.writelines(sql_lines)
        
    print("Executing mini.sql into SQLite DB...")
    if os.path.exists("data/cvefixes/cvefixes_mini.db"):
        os.remove("data/cvefixes/cvefixes_mini.db")
        
    conn = sqlite3.connect("data/cvefixes/cvefixes_mini.db")
    cursor = conn.cursor()
    
    script = "".join(sql_lines)
    cursor.executescript(script)
    
    conn.commit()
    conn.close()
    print("Mini database created!")

if __name__ == "__main__":
    create_mini_db()
