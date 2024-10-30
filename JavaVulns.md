# Java Application Vulnerabilities

## 1. SQL Injection

### Vulnerability
Using untrusted input in SQL queries can lead to SQL injection attacks.

```java
String userInput = request.getParameter("user");
String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

### Remediation
Use prepared statements to safely handle user input.

```java
String userInput = request.getParameter("user");
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, userInput);
ResultSet rs = pstmt.executeQuery();
```

---

## 2. Cross-Site Scripting (XSS)

### Vulnerability
Inserting unescaped user input into web pages can allow XSS attacks.

```java
String userInput = request.getParameter("message");
out.println("<div>" + userInput + "</div>");
```

### Remediation
Escape user input before rendering it in HTML.

```java
String userInput = request.getParameter("message");
String escapedInput = StringEscapeUtils.escapeHtml4(userInput);
out.println("<div>" + escapedInput + "</div>");
```

---

## 3. Insecure Direct Object References (IDOR)

### Vulnerability
Using unvalidated user input to access resources can expose sensitive data.

```java
int fileId = Integer.parseInt(request.getParameter("fileId"));
File file = fileService.getFileById(fileId);
```

### Remediation
Implement access controls to validate user access to the requested resource.

```java
int fileId = Integer.parseInt(request.getParameter("fileId"));
if (!userHasAccessToFile(user, fileId)) {
    throw new SecurityException("Access denied");
}
File file = fileService.getFileById(fileId);
```

---

## 4. Insecure Cryptographic Storage

### Vulnerability
Using weak or deprecated algorithms for encryption can compromise data.

```java
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
```

### Remediation
Use strong encryption algorithms and proper key management.

```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
KeyGenerator keyGen = KeyGenerator.getInstance("AES");
keyGen.init(256);
SecretKey secretKey = keyGen.generateKey();
```

---

## 5. Hardcoded Secrets

### Vulnerability
Hardcoding sensitive information in the source code can lead to leaks.

```java
String password = "SuperSecretPassword123!";
```

### Remediation
Use environment variables or secure vaults to manage secrets.

```java
String password = System.getenv("DB_PASSWORD");
```

---

## 6. Improper Exception Handling

### Vulnerability
Not properly handling exceptions can lead to information leakage.

```java
public void processRequest() {
    try {
        // some code
    } catch (Exception e) {
        e.printStackTrace(); // Exposes stack trace
    }
}
```

### Remediation
Log the exception properly without exposing sensitive information.

```java
public void processRequest() {
    try {
        // some code
    } catch (Exception e) {
        logger.error("An error occurred while processing the request", e);
        throw new CustomException("An error occurred, please try again later");
    }
}
```

---

## 7. Insufficient Logging & Monitoring

### Vulnerability
Not logging critical actions can hinder incident response.

```java
public void deleteUser(int userId) {
    // Deletion code without logging
}
```

### Remediation
Implement logging for critical actions.

```java
public void deleteUser(int userId) {
    logger.info("User with ID " + userId + " is being deleted");
    // Deletion code
}
```

---

## 8. CSRF (Cross-Site Request Forgery)

### Vulnerability
Not validating requests can lead to CSRF attacks.

```java
public void changePassword(String newPassword) {
    // Change password logic
}
```

### Remediation
Implement CSRF tokens to validate requests.

```java
public void changePassword(String newPassword, String csrfToken) {
    if (!isValidCsrfToken(csrfToken)) {
        throw new SecurityException("Invalid CSRF token");
    }
    // Change password logic
}
```

---

## 9. Using Components with Known Vulnerabilities

### Vulnerability
Using outdated libraries can expose the application to known vulnerabilities.

```xml
<dependency>
    <groupId>org.some-library</groupId>
    <artifactId>vulnerable-lib</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Remediation
Regularly update dependencies and use tools to check for vulnerabilities.

```xml
<dependency>
    <groupId>org.some-library</groupId>
    <artifactId>secure-lib</artifactId>
    <version>1.2.3</version>
</dependency>
```

---

## Conclusion
Proper code review processes should always include checks for these common vulnerabilities to enhance the security posture of Java applications.
