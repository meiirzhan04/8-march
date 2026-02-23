import json, csv

with open("advisories.json", "r", encoding="utf-8") as f:
    advisories = json.load(f)

rows = []

for adv in advisories:
    ghsa_id = adv["ghsa_id"]
    source = adv.get("source_code_location", "")
    vulns = adv.get("vulnerabilities", [])

    ecosystem = vulns[0]["package"]["ecosystem"] if vulns else ""

    # по умолчанию пусто
    vuln_old = vuln_new = patch_old = patch_new = ""

    if len(vulns) >= 1:
        vuln_old = vulns[0].get("vulnerable_version_range", "")
        patch_old = vulns[0].get("first_patched_version", "")
    if len(vulns) >= 2:
        vuln_new = vulns[1].get("vulnerable_version_range", "")
        patch_new = vulns[1].get("first_patched_version", "")

    rows.append({
        "ghsa_id": ghsa_id,
        "ecosystem": ecosystem,
        "source_code_location": source,
        "vulnerable_version_old": vuln_old,
        "vulnerable_version_new": vuln_new,
        "patched_version_old": patch_old,
        "patched_version_new": patch_new,
        "old_vuln_patched": "",
        "new_vuln_patch": "",
        "oldvuln_newpatch": ""
    })

# Сохраняем JSON
with open("dataset.json", "w", encoding="utf-8") as f:
    json.dump(rows, f, indent=2, ensure_ascii=False)

# Сохраняем CSV
fieldnames = list(rows[0].keys())
with open("dataset.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
