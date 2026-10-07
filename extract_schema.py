import re

def extract_schema():
    print("Starting schema extraction...")
    tables = {}
    current_table = None
    with open("data/cvefixes/CVEfixes.sqlite", "r", encoding="utf-8", errors="ignore") as f, open("schema.txt", "w") as out:
        for i, line in enumerate(f):
            line = line.strip()
            if line.startswith("CREATE TABLE"):
                current_table = line.split('"')[1] if '"' in line else line.split()[2]
                tables[current_table] = []
                out.write(f"{line}\\n")
            elif current_table:
                out.write(f"{line}\\n")
                if line == ");":
                    current_table = None
            if i % 1000000 == 0:
                print(f"Processed {i} lines")
            if i > 5000000:  # Schema is definitely in first 5M lines
                break

if __name__ == "__main__":
    extract_schema()
