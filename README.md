These are my answers to the two Nucleus Security Interview questions.

The Challenge 1 folder contains the unchanged code that was given to review and then a challenge1notes.txt file which includes my notes on what the code did right/wrong.

The Challenge 2 folder contains an index.html file for the frontend of the problem question and an app.py file for the flask backend of the problem question. This folder also includes a challege2instructions.txt file which just explains what dependencies to download for app.py to work and then how to run it in terminal.

My follow up questions are answered below:
# Webhook Code Review

## Prompt:

> Given an example input data: `{"email":"a@b.com","role":"admin","metadata":{"source":"vendor"}}`
>
> A `/webhook` endpoint to receive vendor events about users who are vendors should be added. It should verify the signature header `X-Signature`, then parse and upsert the user data, then store the raw payload.
>
> Check if the below code does this and break down for me when and how it does it exactly. If it does not do it properly, point where it's incorrect and give me notes on how it should be done properly.

```python
# app.py
import os
import json
import sqlite3
import hashlib
from flask import Flask, request

app = Flask(__name__)
DB_PATH = os.getenv("DB_PATH", "/tmp/app.db")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "dev-secret")  # default for dev

def get_db():
    return sqlite3.connect(DB_PATH)

def verify(sig, body: bytes) -> bool:
    # Vendor docs: SHA256(secret + body)
    expected = hashlib.sha256(
        (WEBHOOK_SECRET + body.decode("utf-8")).encode("utf-8")
    ).hexdigest()
    return expected == sig  # simple compare

@app.post("/webhook")
def webhook():
    raw = request.data  # bytes
    sig = request.headers.get("X-Signature", "")

    if not verify(sig, raw):
        return ("bad sig", 401)

    payload = json.loads(raw.decode("utf-8"))

    # Example payload:
    # {"email":"a@b.com","role":"admin","metadata":{"source":"vendor"}}
    email = payload.get("email", "")
    role = payload.get("role", "user")

    db = get_db()
    cur = db.cursor()

    # Store raw payload for auditing / debugging
    cur.execute(
        f"INSERT INTO webhook_audit(email, raw_json) VALUES ('{email}', '{raw.decode('utf-8')}')"
    )

    # Upsert user
    cur.execute(
        f"INSERT INTO users(email, role) VALUES('{email}', '{role}')"
    )

    db.commit()

    return ("ok", 200)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
```

---

## Claude Output:

### ✅ What It Does Correctly

**Receiving the webhook**
The `@app.post("/webhook")` route correctly accepts POST requests. `request.data` captures the raw bytes before any parsing, which is the right approach — you need the original bytes to verify the signature.

**Signature verification flow**
The structure is correct: read raw body → get header → verify before parsing. This is the right order. Parsing before verifying would be a logic error.

**Storing the raw payload**
The intent to insert into `webhook_audit` for auditing is correct in concept.

---

### ❌ What It Gets Wrong

#### 1. Timing Attack in `verify()` — Medium Severity

```python
return expected == sig  # simple compare
```

Python's `==` on strings short-circuits on the first mismatched character. An attacker can statistically probe which characters of a valid signature are correct by measuring response time. Fix: use `hmac.compare_digest()` which runs in constant time regardless of where strings diverge.

```python
import hmac
return hmac.compare_digest(expected, sig)
```

---

#### 2. SQL Injection in Both Queries — Critical

```python
cur.execute(
    f"INSERT INTO webhook_audit(email, raw_json) VALUES ('{email}', '{raw.decode('utf-8')}')"
)
cur.execute(
    f"INSERT INTO users(email, role) VALUES('{email}', '{role}')"
)
```

Both queries build SQL by directly interpolating user-controlled values into f-strings. A payload like `{"email": "x' OR '1'='1", ...}` would break out of the string literal. The `raw_json` column is even worse — the entire raw body goes straight into the query.

Fix: always use parameterized queries:

```python
cur.execute(
    "INSERT INTO webhook_audit(email, raw_json) VALUES (?, ?)",
    (email, raw.decode("utf-8"))
)
```

---

#### 3. The "Upsert" Is Just an INSERT — Logic Bug

```python
cur.execute(
    f"INSERT INTO users(email, role) VALUES('{email}', '{role}')"
)
```

This is a plain `INSERT`. If the same vendor event fires twice (common with webhooks), or a user already exists, this will either **error out** (if email has a `UNIQUE` constraint) or **create a duplicate row** (if it doesn't). Neither is an upsert.

Fix: use SQLite's upsert syntax:

```python
cur.execute(
    "INSERT INTO users(email, role) VALUES(?, ?) "
    "ON CONFLICT(email) DO UPDATE SET role=excluded.role",
    (email, role)
)
```

---

#### 4. `metadata` Is Silently Dropped

The stated requirement is to parse and upsert user data from payloads like:

```json
{"email":"a@b.com","role":"admin","metadata":{"source":"vendor"}}
```

The code reads `email` and `role` but completely ignores `metadata`. If the users table or a related table is supposed to store `source` or other vendor metadata, that data is lost.

---

#### 5. No Error Handling or DB Cleanup

`json.loads(raw)` will raise an unhandled exception if the body isn't valid JSON, returning a 500 with a stack trace instead of a clean 400. The `db` connection is also never explicitly closed — it relies on garbage collection.

Fix: use `try/finally` or a context manager:

```python
try:
    payload = json.loads(raw)
except json.JSONDecodeError:
    return ("invalid json", 400)

db = get_db()
try:
    # ... queries ...
    db.commit()
finally:
    db.close()
```

---

### Summary

| Check | Status | Issue |
|---|---|---|
| `/webhook` endpoint exists | ✅ | — |
| Reads `X-Signature` header | ✅ | — |
| Verifies before parsing | ✅ | — |
| Constant-time signature compare | ❌ | Use `hmac.compare_digest` |
| Stores raw payload | ✅ *(concept)* | SQL injection vector |
| Parses user fields | ⚠️ | `metadata` ignored |
| Upserts user | ❌ | Plain `INSERT`, not upsert |
| Parameterized SQL | ❌ | Both queries are injectable |
| Error handling | ❌ | No JSON error handling, no DB cleanup |

---

This was the only Prompt I used for the code review. I was hoping for the AI to fully breakdown the code for me to understand what it was doing, and then point out specifically where the given task was implemented and how it was implemented. Then point out whether that implementation was valid or not. 

The AI actually did almost exactly just that, it kind of combined the breaking down and pointing out the task parts of my prompts intention but it was clear enough for me to understand everything and take my notes appropriately.

I did not have the re-prompt it.

If I had to change my approach I would make the AI split up explaining the "breakdown the code" and "where the task was implemented right/wrong" parts. This would allow me to get a deeper understanding of the given code much quicker.

# Calculator Web App Code Challenge

---

## Prompt 1
> Build a calculator web application. It should include a frontend piece and any backend logic needed to perform the calculations. I would like it to add/subtract/multiply/divide. Give me a plan to make it as simple as possible

### Response

Here's the simplest possible plan:

**No backend needed.** Basic arithmetic (+, −, ×, ÷) is trivially handled by JavaScript in the browser — adding a server would only introduce unnecessary complexity.

**The entire app is a single HTML file with 3 parts:**

1. **HTML** — a display screen + buttons (digits 0–9, operators, clear, equals)
2. **CSS** — a clean grid layout for the buttons
3. **JavaScript** — tracks input state and evaluates the expression on "="

**How the logic works:**

- Maintain a string representing the current expression (e.g. `"8 * 3 + 2"`)
- Each button press appends to it
- On `=`, use `eval()` or a simple parser to compute the result
- Handle edge cases: divide by zero, consecutive operators, leading decimals

**Deliverable:** One `.html` file you can open directly in any browser — no install, no server, no dependencies.

Want me to build it? I can have it ready in one shot as a clean, styled single-file app.

---

## Prompt 2
> Make it as simple as possible WITH a backend AND frontend piece

### Response

Got it. Here's the plan I'll execute:

- **Backend:** Python + Flask, one endpoint `/calculate` that receives two numbers and an operator, returns the result
- **Frontend:** Single `index.html` that sends `fetch()` requests to the backend

**`app.py` — Flask backend**

- One route: `POST /calculate`
- Accepts `{ a, b, op }` as JSON, returns `{ result }` or `{ error }`
- Handles divide-by-zero and bad input

**`index.html` — Frontend**

- Opens directly in any browser
- Each `=` press sends a `fetch()` to `localhost:5000/calculate` and displays the result
- Also supports keyboard input

**To run:**

```bash
pip install flask flask-cors
python app.py
# then open index.html in your browser
```
---

I was able to make a fully functioning rudimentary calculator that adds, subtracts, multiplys and divides in the given time.

The only challenge I encountered was claude forgetting to give me one flask dependency to download, which the terminal error code told me, so I downloaded it manually without asking claude.

If I was given unlimited time, I would add exponent and logarithmic functions, the ability to square and square root and all the trig functions!

I did use AI, and the AI did really well creating a lightweight minimal dependecy dependent application with full frontend and backend parts. What the AI did a little poorly was explain how to run it, but it was so minor that it was self-explanatory. I did not really have to change prompts to improve its output for that explanation error, I did have to reprompt it as it suggested a frontend only option to create this calculator.
