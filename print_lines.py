def print_lines(start, end):
    with open("data/cvefixes/CVEfixes.sqlite", "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= start and i <= end:
                print(f"Line {i}: {line[:200]}...")
            if i > end:
                break

if __name__ == "__main__":
    print_lines(45511, 45516)
    print_lines(16184, 16189)
