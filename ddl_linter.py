import re

DANGEROUS_DDL = [
    (re.compile(r"DROP\s+COLUMN", re.IGNORECASE), "BREAKING: Dropping a column breaks active app instances still reading it. Use expand-contract."),
    (re.compile(r"MODIFY\s+COLUMN.*NOT\s+NULL", re.IGNORECASE), "LOCK RISK: Adding NOT NULL without default can trigger full table copy in MySQL."),
    (re.compile(r"RENAME\s+COLUMN", re.IGNORECASE), "BREAKING: Renaming breaks backward compatibility during rolling deploys."),
]

def lint_migration(sql: str) -> list[str]:
    warnings = []
    for pattern, message in DANGEROUS_DDL:
        if pattern.search(sql):
            warnings.append(message)
    return warnings or ["SAFE: No blocking or backward-incompatible DDL detected."]

if __name__ == "__main__":
    print(lint_migration("ALTER TABLE users DROP COLUMN legacy_token;"))
