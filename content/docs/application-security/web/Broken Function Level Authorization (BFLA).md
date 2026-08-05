---
title: Broken Function Level Authorization
---

# Broken Function Level Authorization (BFLA)

## Description

Broken Function Level Authorization (BFLA) occurs when an application fails to properly verify whether an authenticated user has permission to execute a specific function or action. As a result, low-privileged users may gain access to administrative, management, or other privileged functionalities that should be restricted.

BFLA is one of the most common API security issues and is frequently caused by missing or inconsistent authorization checks on backend endpoints. Applications often enforce restrictions in the user interface while failing to validate permissions on the server side, allowing attackers to directly invoke privileged functions through crafted requests.

**BFLA differs from BOLA (IDOR).** BOLA focuses on unauthorized access to specific objects or resources (e.g., another user's record), whereas BFLA focuses on unauthorized execution of privileged functions (e.g., creating users, exporting data, approving transactions, changing roles).

**Maps to:**

- OWASP API5:2023 – Broken Function Level Authorization
- OWASP A01:2021 – Broken Access Control
- CWE-285 – Improper Authorization
- CWE-862 – Missing Authorization

---

## Fundamentals

### Authorization Models

**Role-Based Access Control (RBAC)**

- Permissions are assigned based on predefined roles.
- Example: User, Manager, Admin.

**Attribute-Based Access Control (ABAC)**

- Access decisions are based on user attributes, resource attributes, and contextual conditions.

**Policy-Based Access Control (PBAC)**

- Access is determined through centrally defined authorization policies.

**Least Privilege Principle**

- Users should only have access to the minimum functionality required for their role.

### The Authorization Gap

Many applications properly authenticate users but fail to verify whether they are authorized to perform specific actions.

Example:

1. User logs in successfully.
2. User discovers an administrative endpoint.
3. User sends a request directly to the endpoint.
4. Backend verifies authentication but skips authorization checks.
5. Privileged action is executed.

### Common Naming Conventions

Administrative functionality often uses predictable naming patterns:

```
admin
administrator
manage
management
internal
console
dashboard
super
root
system
config
debug
export
import
backup
sync
approve
upgrade
invite
```

---

## Attack Surface

- Administrative APIs
- User management endpoints
- Role management functionality
- Feature flag APIs
- Billing and subscription APIs
- Approval workflows
- Import/export functionality
- Backup and restore endpoints
- System configuration APIs
- Internal APIs
- Mobile application APIs
- GraphQL mutations
- Debug endpoints
- Health check endpoints
- CI/CD administration interfaces
- Legacy API versions
- Hidden administrative panels
- Subdomains exposing management functions

---

## Exploitation Techniques

### 1. Vertical Privilege Escalation

A lower-privileged user accesses functions intended for higher roles.

**Example**

```
GET /api/v1/profile
```

Allowed for normal users.

```
POST /api/v1/admin/create-user
```

Attempt using a regular user token.

Potential impact:

- User creation
- Role modification
- Administrative access

---

### 2. Hidden Function Discovery

Administrative endpoints may exist even when no UI element exposes them.

Common locations:

```
/admin
/manage
/dashboard
/system
/internal
/console
/api/admin
/api/system
/api/manage
```

Sources for discovery:

- JavaScript files
- Swagger/OpenAPI documentation
- Mobile applications
- Postman collections
- Wayback Machine
- robots.txt

---

### 3. HTTP Method Abuse

Authorization may only be implemented for certain HTTP methods.

Example:

```
GET /api/users
```

Blocked.

```
POST /api/users
PUT /api/users
PATCH /api/users
DELETE /api/users
```

Unexpectedly allowed.

Test:

```
X-HTTP-Method-Override: DELETE
```

---

### 4. Workflow and Approval Bypass

Applications often expose privileged approval actions through APIs.

Examples:

```
Approve Refund
Approve Withdrawal
Approve Loan
Approve KYC
Approve User
Approve Transaction
```

Example request:

```
POST /api/approval/refund/123
```

Executed using a standard user account.

---

### 5. Role Manipulation Functions

Look for functionality involving:

```
role
permission
group
membership
tier
plan
access
```

Examples:

```
POST /api/users/promote
POST /api/users/change-role
POST /api/permissions/grant
```

---

### 6. Feature Flag Abuse

Feature management APIs frequently suffer from authorization weaknesses.

Examples:

```
POST /api/features/enable
POST /api/feature/premium
POST /api/feature/beta
```

Potential impact:

- Premium feature access
- Internal feature access
- Administrative functionality exposure

---

### 7. GraphQL Mutation Abuse

GraphQL often exposes privileged functionality through mutations.

Examples:

```
mutation {
  deleteUser(id: 10)
}
```

```
mutation {
  promoteUser(id: 10, role: "ADMIN")
}
```

```
mutation {
  exportAllUsers
}
```

---

### 8. API Version Abuse

Legacy versions may lack authorization checks.

Examples:

```
/api/v1/admin/export
/api/v2/admin/export
/api/v3/admin/export
```

Test:

```
v1
v2
legacy
beta
internal
old
```

---

## Test Cases

| Test | Action |
| --- | --- |
| Admin Panel Access | Access administrative endpoints using a low-privileged account |
| User Management | Create, delete, or modify users |
| Role Modification | Promote or demote accounts |
| Export Functions | Export reports, logs, or databases |
| Billing Actions | Modify subscriptions or payments |
| Workflow Actions | Approve or reject business operations |
| Feature Management | Enable restricted features |
| Backup Access | Download backups or configuration files |
| GraphQL Mutations | Execute privileged mutations |
| API Versions | Test legacy endpoints |

---

## Bypass Techniques

### Header-Based Authorization Bypass

Applications sometimes trust client-controlled headers.

Examples:

```
X-User-Role: admin
X-Role: admin
X-Admin: true
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Prefix: /admin
X-Custom-IP-Authorization: 127.0.0.1
```

---

### Case Manipulation

```
/Admin
/ADMIN
/aDmIn
```

---

### Path Traversal & Normalization

```
/admin/..
/api/user/../admin
/admin/%2e%2e/
/admin/./
```

---

### URL Encoding

```
%2fadmin
%252fadmin
```

---

### Double Slash Bypass

```
//admin
/api//admin
```

---

### Trailing Slash / Dot

```
/admin/
/admin.
/admin..
```

---

### Alternate API Versions

```
v1
v2
legacy
beta
internal
old
```

---

### Parameter-Based Overrides

Examples:

```
POST /api/user/update?admin=true
```

```
POST /api/user/update?role=admin
```

```
POST /api/user/update?isAdmin=1
```

---

## Detection Techniques

### Manual Testing

**Build a Role Matrix**

Compare functionality across:

```
Anonymous
User
Manager
Support
Admin
Super Admin
```

Attempt privileged requests using lower-privileged accounts.

**Review API Documentation**

Look for:

```
swagger.json
openapi.json
api-docs
Postman collections
```

**Analyze Client-Side Code**

Review:

- JavaScript files
- Mobile applications
- GraphQL schemas
- Hidden buttons
- Disabled functionality

**Compare Responses**

Compare:

```
Status Codes
Response Bodies
Response Lengths
Error Messages
```

Across different roles.

---

## Automated Detection

**Autorize:** Replay requests using different sessions to identify authorization issues.

**AuthMatrix**: Build role-based testing matrices and automatically compare results.

**Kiterunner:** Discover hidden API endpoints and administrative functionality.

**GraphQL Testing**

Enumerate:

```
Query
Mutation
Subscription
```

and test authorization controls.

---

# Impact

- Vertical privilege escalation.
- Unauthorized administrative access.
- Complete application compromise.
- User account manipulation.
- Role escalation to administrator.
- Unauthorized approval of business processes.
- Financial fraud and transaction manipulation.
- Data modification or deletion.
- Mass data exposure through export functionality.
- Service disruption and operational impact.
- Compliance and regulatory violations.
- Loss of confidentiality, integrity, and availability.

---

# Prevention

- Enforce authorization checks on every request and function.
- Implement centralized authorization middleware.
- Follow a deny-by-default authorization model.
- Use robust RBAC, ABAC, or PBAC controls.
- Validate permissions on the server side only.
- Never rely on hidden UI elements for security.
- Apply authorization checks consistently across all API versions.
- Protect GraphQL mutations with proper authorization rules.
- Review and secure administrative endpoints.
- Restrict access to internal functionality.
- Log and monitor privileged actions.
- Perform regular authorization testing during development and security assessments.
- Conduct code reviews focused on access control logic.
- Implement least privilege principles for all users and roles.

---

# Tools

- **Autorize** – Automated authorization testing using multiple user sessions.
- **AuthMatrix** – Build and test role-based access control matrices.
- **InQL** – GraphQL endpoint enumeration and testing.

---

# Good to Read

- [Information Disclosure via GIF](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwitmsPGrIuTAxW9TWwGHVkxHA4QFnoECBkQAQ&url=https%3A%2F%2Fhackerone.com%2Freports%2F1801427&usg=AOvVaw09Q5FGF3qCFQw8NB3JvKgo&opi=89978449)
- [Accessing restricted analytics functions via BFLA.](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwi7p4aXrIuTAxV1VmwGHe2HN2YQFnoECBsQAQ&url=https%3A%2F%2Fhackerone.com%2Freports%2F2632876&usg=AOvVaw30UoTqXAzAjDru3EV26vkq&opi=89978449)
- [Linkedin Draft Post Disclosure](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwitmsPGrIuTAxW9TWwGHVkxHA4QFnoECCAQAQ&url=https%3A%2F%2Fhackerone.com%2Freports%2F1675674&usg=AOvVaw3L0UdF6WEfQ642t9kp7-lx&opi=89978449)

---

# References

- OWASP API Security Top 10 (API5:2023): [https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- OWASP Broken Access Control: [https://owasp.org/Top10/A01_2021-Broken_Access_Control/](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- PortSwigger Access Control Vulnerabilities: [https://portswigger.net/web-security/access-control](https://portswigger.net/web-security/access-control)
- CWE-285 Improper Authorization: [https://cwe.mitre.org/data/definitions/285.html](https://cwe.mitre.org/data/definitions/285.html)
- CWE-862 Missing Authorization: [https://cwe.mitre.org/data/definitions/862.html](https://cwe.mitre.org/data/definitions/862.html)