# OWASP Top 10 Risks and Mitigations

---

## 1. OWASP Web Application Security Top 10 (2021)

| **Risk**                                | **Description**                                                                                  | **Mitigation**                                                                                 |
|-----------------------------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| **A01: Broken Access Control**          | Improper enforcement of user permissions, allowing unauthorized access.                         | Implement role-based access control (RBAC), enforce least privilege, and test authorization.  |
| **A02: Cryptographic Failures**         | Insecure data storage or transmission due to weak encryption practices.                         | Use strong encryption protocols (TLS 1.2/1.3), secure key management, and avoid plaintext storage. |
| **A03: Injection**                      | Code injection flaws (e.g., SQL, OS, LDAP) allowing attackers to execute malicious commands.    | Use prepared statements, parameterized queries, and input validation.                         |
| **A04: Insecure Design**                | Security issues stemming from design flaws and lack of security measures during development.    | Adopt a secure software development lifecycle (SDLC), perform threat modeling, and code reviews. |
| **A05: Security Misconfiguration**      | Improper system or application configurations leading to vulnerabilities.                       | Automate configuration management, disable unused services, and apply security benchmarks.    |
| **A06: Vulnerable and Outdated Components** | Use of outdated libraries, frameworks, or software components with known vulnerabilities.       | Regularly patch and update dependencies, use SCA tools to detect vulnerable components.       |
| **A07: Identification and Authentication Failures** | Weak authentication mechanisms, leading to account compromise or session issues.               | Use multi-factor authentication (MFA), strong password policies, and secure session management. |
| **A08: Software and Data Integrity Failures** | Compromised software updates, libraries, or insecure CI/CD pipelines.                          | Implement digital signatures, secure CI/CD pipelines, and verify software integrity.          |
| **A09: Security Logging and Monitoring Failures** | Lack of logging, monitoring, and detection mechanisms to identify attacks.                     | Enable security logging, use SIEM systems, and monitor critical events.                       |
| **A10: Server-Side Request Forgery (SSRF)** | Applications fetching remote resources are tricked into accessing internal systems.             | Validate and sanitize user inputs, enforce allow-lists for URLs, and restrict network access. |

---

## 2. OWASP LLM Top 10 (2023)

| **Risk**                                | **Description**                                                                                  | **Mitigation**                                                                                 |
|-----------------------------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| **LLM01: Prompt Injection**             | Manipulating prompts to make LLMs execute unintended actions or generate harmful responses.     | Use input sanitization, implement context filtering, and limit user-supplied inputs.          |
| **LLM02: Insecure Output Handling**     | Insufficient validation of LLM-generated content, causing downstream issues.                   | Validate and filter LLM output before usage, enforce content safety policies.                 |
| **LLM03: Training Data Poisoning**      | Malicious data injected into training datasets to influence model behavior.                    | Verify and sanitize training data, and monitor for anomalies during training.                 |
| **LLM04: Model Denial of Service (DoS)** | Overloading LLMs with resource-intensive queries, leading to unavailability.                   | Implement rate-limiting, input validation, and query complexity checks.                       |
| **LLM05: Supply Chain Vulnerabilities** | Exploiting third-party libraries, APIs, or datasets used in LLM development.                   | Perform regular dependency checks, verify third-party components, and apply software updates. |
| **LLM06: Sensitive Information Disclosure** | Accidental exposure of sensitive information present in training data.                        | Anonymize training data, implement strict data access controls, and validate outputs.         |
| **LLM07: Insecure Plugin Design**       | Weak integrations with plugins/extensions that expose security flaws.                          | Perform security testing on plugins, enforce secure APIs, and validate plugin permissions.    |
| **LLM08: Excessive Agency**             | Allowing LLMs too much autonomy in performing actions, leading to unintended consequences.     | Set clear limits on autonomous actions and require human validation for critical tasks.       |
| **LLM09: Overreliance on LLMs**         | Trusting LLM output without validation, leading to misinformation or errors.                   | Implement human-in-the-loop validation and verify outputs against trusted sources.            |
| **LLM10: Model Theft**                  | Unauthorized access or copying of LLM architectures, weights, or intellectual property.        | Use encryption for models, secure storage, and access controls to prevent unauthorized access. |

---

## 3. OWASP Mobile Application Security Top 10 (2016)

| **Risk**                                | **Description**                                                                                  | **Mitigation**                                                                                 |
|-----------------------------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| **M1: Improper Platform Usage**         | Misusing mobile OS features like permissions, intents, or storage.                              | Follow platform-specific security guidelines and limit app permissions.                       |
| **M2: Insecure Data Storage**           | Storing sensitive data insecurely on the device, exposing it to attackers.                      | Encrypt sensitive data, use secure storage APIs, and avoid storing unnecessary data.          |
| **M3: Insecure Communication**          | Weak encryption or unprotected transmission of data over networks.                              | Use TLS/SSL for all communications, implement certificate pinning, and avoid plaintext data.  |
| **M4: Insecure Authentication**         | Flaws in user authentication mechanisms, allowing unauthorized access.                          | Use secure authentication (e.g., OAuth, JWT), enforce strong password policies, and MFA.      |
| **M5: Insufficient Cryptography**       | Weak or flawed cryptographic implementations for sensitive data.                                | Use strong encryption libraries, avoid hardcoding keys, and ensure proper cryptographic algorithms. |
| **M6: Insecure Authorization**          | Improper enforcement of user permissions, leading to privilege escalation.                      | Implement role-based access control and verify all user actions against authorization rules.  |
| **M7: Client Code Quality**             | Poor coding practices resulting in vulnerabilities like buffer overflows.                       | Perform secure coding reviews, static analysis, and use memory-safe programming practices.    |
| **M8: Code Tampering**                  | Altering or injecting code into the application to change behavior.                             | Use anti-tampering tools, verify app integrity with checksums, and obfuscate sensitive code.  |
| **M9: Reverse Engineering**             | Extracting code, algorithms, or sensitive information via decompilation tools.                  | Use code obfuscation, encrypt sensitive logic, and add anti-reverse engineering protections.  |
| **M10: Extraneous Functionality**       | Including hidden or unnecessary functionality that can be abused.                               | Remove debug features, conduct code reviews, and test for hidden or unused functionality.     |

---

