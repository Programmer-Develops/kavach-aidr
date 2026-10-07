import re

def check_dump():
    tables = []
    with open("data/cvefixes/CVEfixes.sqlite", "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if line.startswith("CREATE TABLE"):
                tables.append(line.strip())
                print(f"Line {i}: {line.strip()}")
            if i > 500000 and len(tables) > 5:
                break
    print("Tables found:", tables)

if __name__ == "__main__":
    check_dump()
