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

## 10. Command Injection

### Vulnerability
Using untrusted input in system command execution can lead to command injection.

```java
String command = "ls " + request.getParameter("path");
Runtime.getRuntime().exec(command);
```

### Remediation
Validate and sanitize user input or use safer APIs.

```java
String path = request.getParameter("path");
// Validate path against allowed values
if (!isValidPath(path)) {
    throw new SecurityException("Invalid path");
}
ProcessBuilder pb = new ProcessBuilder("ls", path);
pb.start();
```

---

## 11. Unvalidated Redirects and Forwards

### Vulnerability
Redirecting users based on unvalidated input can lead to phishing attacks.

```java
String targetUrl = request.getParameter("redirect");
response.sendRedirect(targetUrl);
```

### Remediation
Use a whitelist of allowed URLs for redirection.

```java
String targetUrl = request.getParameter("redirect");
if (!isValidRedirect(targetUrl)) {
    throw new SecurityException("Invalid redirect URL");
}
response.sendRedirect(targetUrl);
```

---

## 12. Insufficient Input Validation

### Vulnerability
Failing to validate input data can lead to various attacks.

```java
String ageStr = request.getParameter("age");
int age = Integer.parseInt(ageStr); // Could throw NumberFormatException
```

### Remediation
Always validate input before processing.

```java
String ageStr = request.getParameter("age");
if (!isValidAge(ageStr)) {
    throw new IllegalArgumentException("Invalid age");
}
int age = Integer.parseInt(ageStr);
```

---

## 13. Session Fixation

### Vulnerability
Allowing a user to continue using an old session ID can lead to session fixation attacks.

```java
// Login logic without regenerating session ID
HttpSession session = request.getSession();
session.setAttribute("user", user);
```

### Remediation
Regenerate the session ID after authentication.

```java
HttpSession session = request.getSession();
session.invalidate(); // Invalidate old session
session = request.getSession(true); // Create a new session
session.setAttribute("user", user);
```

---

## 14. Directory Traversal

### Vulnerability
Using untrusted input to access files can lead to directory traversal attacks.

```java
String fileName = request.getParameter("file");
File file = new File("/data/" + fileName);
```

### Remediation
Sanitize input to prevent path manipulation.

```java
String fileName = request.getParameter("file");
if (!isValidFileName(fileName)) {
    throw new SecurityException("Invalid file name");
}
File file = new File("/data/" + fileName);
```

---

## 15. Resource Exhaustion

### Vulnerability
Uncontrolled input can lead to resource exhaustion, such as excessive memory or CPU usage.

```java
public void processInput(String input) {
    List<String> items = new ArrayList<>();
    for (int i = 0; i < input.length(); i++) {
        items.add(input); // Potential for excessive memory use
    }
}
```

### Remediation
Limit input size and validate it.

```java
public void processInput(String input) {
    if (input.length() > MAX_LENGTH) {
        throw new IllegalArgumentException("Input too long");
    }
    // Process input
}
```

---

## 16. Lack of HTTPS

### Vulnerability
Not using HTTPS can expose sensitive data in transit.

```java
// Application is served over HTTP
```

### Remediation
Configure the application server to use HTTPS.

```xml
<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
           clientAuth="false" sslProtocol="TLS" />
```

---

## 17. Deserialization Vulnerabilities

### Vulnerability
Deserializing untrusted data can lead to remote code execution.

```java
ObjectInputStream in = new ObjectInputStream(new FileInputStream("data.obj"));
MyObject obj = (MyObject) in.readObject(); // Unsafe deserialization
```

### Remediation
Avoid deserializing untrusted data or implement strict validation.

```java
ObjectInputStream in = new ObjectInputStream(new FileInputStream("data.obj")) {
    @Override
    protected Object readObject() throws IOException, ClassNotFoundException {
        // Implement custom validation logic
        return super.readObject();
    }
};
MyObject obj = (MyObject) in.readObject();
```

---

## 18. Server-Side Request Forgery (SSRF)

### Vulnerability
Allowing user input to control server-side requests can lead to SSRF attacks.

```java
String url = request.getParameter("url");
URLConnection connection = new URL(url).openConnection();
InputStream response = connection.getInputStream(); // Uncontrolled request
```

### Remediation
Validate and restrict the target URLs.

```java
String url = request.getParameter("url");
if (!isValidUrl(url)) {
    throw new SecurityException("Invalid URL");
}
URLConnection connection = new URL(url).openConnection();
InputStream response = connection.getInputStream();
```

---

## 19. Insecure Configuration

### Vulnerability
Using default configurations or exposing sensitive information in configuration files.

```xml
<property name="db.password">password123</property>
```

### Remediation
Remove sensitive information from configuration files and use secure configurations.

```xml
<property name="db.password">${env.DB_PASSWORD}</property>
```

---

## 20. Exposure of Sensitive Data in Logs

### Vulnerability
Logging sensitive data can lead to data exposure.

```java
logger.info("User logged in: " + username + ", password: " + password);
```

### Remediation
Avoid logging sensitive information.

```java
logger.info("User logged in: " + username);
```

---

## 21. Improper Certificate Validation

### Vulnerability
Failing to validate SSL certificates can lead to man-in-the-middle attacks.

```java
HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
conn.connect(); // No certificate validation
```

### Remediation
Implement proper SSL certificate validation.

```java
HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
conn.setSSLSocketFactory(sslContext.getSocketFactory()); // Use validated context
conn.connect();
```

---

## 22. Non-Constant Time Comparisons

### Vulnerability
Using standard comparison methods can lead to timing attacks.

```java
if (password.equals(storedPassword)) {
    // Passwords match
}
```

### Remediation
Use a constant-time comparison method.

```java
if (ConstantTimeComparator.equals(password.getBytes(), storedPassword.getBytes())) {
    // Passwords match
}
```

---

## 23. Overly Permissive CORS

### Vulnerability
Setting overly permissive Cross-Origin Resource Sharing (CORS) headers can expose APIs.

```java
response.setHeader("Access-Control-Allow-Origin", "*"); // Allows all origins
```

### Remediation
Restrict CORS to trusted origins.

```java
response.setHeader("Access-Control-Allow-Origin", "https://trusted.com");
```

---

## 24. Unrestricted File Uploads

### Vulnerability
Allowing users to upload files without validation can lead to malicious file uploads.

```java
Part filePart = request.getPart("file");
filePart.write("/uploads/" + filePart.getSubmittedFileName()); // No validation
```

### Remediation
Validate file types and sizes before accepting uploads.

```java
if (!isValidFileType(filePart.getContentType())) {
    throw new SecurityException("Invalid file type");
}
filePart.write("/uploads/" + filePart.getSubmittedFileName());
```

---

## 25. Lack of Rate Limiting

### Vulnerability
Not implementing rate limiting can lead to brute force attacks.

```java
public void login(String username, String password) {
    // Login logic without rate limiting
}
```

### Remediation
Implement rate limiting to restrict repeated attempts.

```java
if (isRateLimited(username)) {
    throw new SecurityException("Too many login attempts");
}
login(username, password);
```

---

## 26. Misconfigured Security Headers

### Vulnerability
Not setting security-related HTTP headers can lead to various attacks.

```java
// No security headers set
```

### Remediation
Set appropriate security headers.

```java
response.setHeader("X-Content-Type-Options", "nosniff");
response.setHeader("X-XSS-Protection", "1; mode=block");
response.setHeader("Content-Security-Policy", "default-src 'self'");
```

---

## 27. Using Weak Password Hashing

### Vulnerability
Using outdated or weak hashing algorithms for passwords can lead to easy cracking.

```java
String hashedPassword = hash(password); // Weak hash function
```

### Remediation
Use strong hashing algorithms with salting, such as BCrypt.

```java
String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
```

---

## 28. Insufficient Session Expiration

### Vulnerability
Not expiring sessions after a certain time can leave users vulnerable.

```java
// Session does not expire
```

### Remediation
Set a timeout for user sessions.

```java
session.setMaxInactiveInterval(30 * 60); // 30 minutes
```

---


## 29. Use of Insecure Random Number Generation

### Vulnerability
Using `Math.random()` or similar for security purposes can lead to predictable results.

```java
String token = String.valueOf(Math.random()); // Insecure random generation
```

### Remediation
Use a secure random number generator.

```java
SecureRandom secureRandom = new SecureRandom();
byte[] randomBytes = new byte[16];
secureRandom.nextBytes(randomBytes);
String token = Base64.getEncoder().encodeToString(randomBytes);
```

---

## 30. Improper Use of Serialization

### Vulnerability
Serializing sensitive objects can expose data when transmitted or stored.

```java
ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("data.ser"));
out.writeObject(sensitiveData); // Direct serialization of sensitive data
```

### Remediation
Avoid serializing sensitive data or use custom serialization methods.

```java
private void writeObject(ObjectOutputStream out) throws IOException {
    // Custom serialization logic to exclude sensitive fields
}
```

---

## 31. Race Conditions

### Vulnerability
Improper handling of shared resources can lead to race conditions.

```java
public void updateBalance(double amount) {
    balance += amount; // Not thread-safe
}
```

### Remediation
Synchronize access to shared resources.

```java
public synchronized void updateBalance(double amount) {
    balance += amount; // Thread-safe
}
```

---

## 32. Failure to Restrict URL Access

### Vulnerability
Not properly restricting access to sensitive URLs can expose resources.

```java
@WebServlet("/admin")
public class AdminServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        // Admin logic without access control
    }
}
```

### Remediation
Implement access control checks.

```java
@WebServlet("/admin")
public class AdminServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        if (!userIsAdmin(request)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        // Admin logic
    }
}
```

---

## 33. Flawed Business Logic

### Vulnerability
Incorrect implementation of business rules can lead to vulnerabilities.

```java
public void applyDiscount(User user, double amount) {
    if (user.getRole() == Role.VIP) {
        amount *= 0.9; // Incorrectly applied discount
    }
}
```

### Remediation
Ensure business logic is thoroughly tested and validated.

```java
public void applyDiscount(User user, double amount) {
    if (user.getRole() == Role.VIP && user.hasValidDiscount()) {
        amount *= 0.9; // Apply discount only if valid
    }
}
```

---

## 34. Information Leakage through Error Messages

### Vulnerability
Displaying detailed error messages can reveal sensitive information.

```java
try {
    // Some operation
} catch (SQLException e) {
    e.printStackTrace(); // Exposes stack trace
}
```

### Remediation
Log errors internally and show user-friendly messages.

```java
try {
    // Some operation
} catch (SQLException e) {
    logger.error("Database error occurred", e);
    throw new CustomException("An error occurred, please try again.");
}
```

---

## 35. Insecure HTTP Methods

### Vulnerability
Allowing unsafe HTTP methods can expose sensitive operations.

```java
// No restrictions on HTTP methods
```

### Remediation
Restrict HTTP methods to safe ones.

```java
@Override
protected void doGet(HttpServletRequest request, HttpServletResponse response) {
    // Handle GET requests only
}
```

---

## 36. Lack of Input Sanitization

### Vulnerability
Not sanitizing user input can lead to various injection attacks.

```java
String username = request.getParameter("username"); // Unvalidated input
```

### Remediation
Sanitize input to remove potentially harmful characters.

```java
String username = sanitizeInput(request.getParameter("username"));
```

---

## 37. Insecure Deserialization of Untrusted Data

### Vulnerability
Deserializing untrusted data can lead to arbitrary code execution.

```java
ObjectInputStream in = new ObjectInputStream(new FileInputStream("data.obj")); 
MyObject obj = (MyObject) in.readObject(); // Unchecked deserialization
```

### Remediation
Implement checks or use a safe deserialization library.

```java
if (!isSafeObject(in)) {
    throw new SecurityException("Unsafe object detected");
}
MyObject obj = (MyObject) in.readObject();
```

---

## 38. Uncontrolled Resource Consumption

### Vulnerability
Allowing unlimited resources (like memory or CPU) can lead to denial-of-service attacks.

```java
public void processLargeInput(String input) {
    List<String> items = new ArrayList<>();
    for (int i = 0; i < input.length(); i++) {
        items.add(input); // Potentially unbounded memory usage
    }
}
```

### Remediation
Limit input size and resource usage.

```java
public void processLargeInput(String input) {
    if (input.length() > MAX_LENGTH) {
        throw new IllegalArgumentException("Input too large");
    }
    // Process input safely
}
```

---

## 39. Misconfigured Default Accounts

### Vulnerability
Leaving default accounts (like admin) enabled without strong credentials can be risky.

```xml
<property name="admin.username">admin</property>
<property name="admin.password">password</property>
```

### Remediation
Disable or secure default accounts.

```xml
<property name="admin.username">secureAdmin</property>
<property name="admin.password">${env.ADMIN_PASSWORD}</property>
```

---

## 40. Poorly Managed Dependencies

### Vulnerability
Using outdated or vulnerable third-party libraries can expose the application.

```xml
<dependency>
    <groupId>org.example</groupId>
    <artifactId>old-library</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Remediation
Regularly review and update dependencies.

```xml
<dependency>
    <groupId>org.example</groupId>
    <artifactId>updated-library</artifactId>
    <version>1.2.0</version>
</dependency>
```

---


## 41. Failure to Implement Proper Authentication

### Vulnerability
Not implementing robust authentication can allow unauthorized access.

```java
public void login(String username, String password) {
    if (username.equals("admin") && password.equals("admin")) {
        // Grant access without proper checks
    }
}
```

### Remediation
Use a proper authentication mechanism.

```java
public void login(String username, String password) {
    User user = userService.findByUsername(username);
    if (user != null && passwordEncoder.matches(password, user.getPassword())) {
        // Grant access
    } else {
        throw new SecurityException("Invalid credentials");
    }
}
```

---

## 42. Insufficient Session Management

### Vulnerability
Failing to manage sessions correctly can allow session hijacking.

```java
HttpSession session = request.getSession();
session.setAttribute("user", user); // No expiration or revalidation
```

### Remediation
Implement session expiration and revalidation.

```java
HttpSession session = request.getSession();
session.setMaxInactiveInterval(30 * 60); // 30 minutes
// Revalidate session on sensitive actions
```

---

## 43. Lack of Account Lockout Mechanism

### Vulnerability
Not implementing account lockout can allow brute-force attacks.

```java
public void login(String username, String password) {
    // No lockout after failed attempts
}
```

### Remediation
Implement account lockout after a specified number of failed attempts.

```java
if (failedAttempts > MAX_FAILED_ATTEMPTS) {
    throw new SecurityException("Account locked due to too many failed attempts");
}
```

---

## 44. Insecure Use of `eval()` or Similar Methods

### Vulnerability
Using `eval()` or similar methods can execute arbitrary code.

```java
String input = request.getParameter("code");
eval(input); // Dangerous execution
```

### Remediation
Avoid using `eval()` or similar constructs.

```java
// Instead, implement a safe execution environment or parser
```

---

## 45. Missing Security Patches

### Vulnerability
Not applying security patches to libraries or frameworks can leave the application vulnerable.

```xml
<dependency>
    <groupId>org.vulnerable</groupId>
    <artifactId>vulnerable-lib</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Remediation
Regularly check for and apply security patches.

```xml
<dependency>
    <groupId>org.vulnerable</groupId>
    <artifactId>secure-lib</artifactId>
    <version>1.2.0</version>
</dependency>
```

---

## 46. Unprotected APIs

### Vulnerability
Exposing APIs without authentication or authorization can lead to unauthorized access.

```java
@WebServlet("/publicApi")
public class PublicApiServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        // Open API access
    }
}
```

### Remediation
Secure APIs with proper authentication and authorization.

```java
@WebServlet("/secureApi")
public class SecureApiServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        if (!isAuthenticated(request)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        // Handle authenticated requests
    }
}
```

---

## 47. Misconfigured Database Permissions

### Vulnerability
Granting excessive database permissions can lead to data breaches.

```sql
GRANT ALL PRIVILEGES ON database.* TO 'user'@'host';
```

### Remediation
Follow the principle of least privilege when granting permissions.

```sql
GRANT SELECT, INSERT, UPDATE ON database.* TO 'user'@'host';
```

---

## 48. Overly Broad Exception Handling

### Vulnerability
Catching generic exceptions can hide underlying issues and security problems.

```java
try {
    // Some operation
} catch (Exception e) {
    // Overly broad catch
}
```

### Remediation
Catch specific exceptions to handle errors appropriately.

```java
try {
    // Some operation
} catch (SQLException e) {
    logger.error("Database error", e);
} catch (IOException e) {
    logger.error("IO error", e);
}
```

---

## 49. Ineffective Use of Logging

### Vulnerability
Logging sensitive information or not logging important events can lead to security issues.

```java
logger.debug("User password: " + password); // Sensitive data logged
```

### Remediation
Avoid logging sensitive information and log relevant events appropriately.

```java
logger.info("User " + username + " logged in");
```

---

## 50. Inadequate Input Length Checks

### Vulnerability
Not checking input length can lead to buffer overflow or denial of service.

```java
String input = request.getParameter("input");
String[] parts = input.split(","); // No length check
```

### Remediation
Implement input length checks.

```java
String input = request.getParameter("input");
if (input.length() > MAX_LENGTH) {
    throw new IllegalArgumentException("Input too long");
}
```

---
