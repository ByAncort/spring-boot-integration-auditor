# OWASP Top 10 (2021) — Spring Boot Checks

> Part of the `spring-boot-integration-auditor` skill — back to [SKILL.md](../SKILL.md)

Each category lists: detection commands, vulnerable Spring patterns, severity, and the secure Spring Boot 3.x alternative. For complete code examples see `spring-boot-patterns.md`.

---

## A01:2021 — Broken Access Control

**Risk**: User accesses data/functionality they should not. Privilege escalation, IDOR, missing tenant isolation.

### Detection commands

```bash
# Controllers without method security
rg -n "@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)" src/ --type java \
  | rg -v "@PreAuthorize|@Secured|@RolesAllowed"

# Insecure authority checks
rg -in "(hasRole|hasAuthority).*ROLE_ADMIN" src/ --type java

# Hardcoded role checks
rg -in "getAuthorities\(\)\.contains|role\.equals\(" src/ --type java

# Spring Security configuration
rg -n "SecurityFilterChain|antMatchers|requestMatchers" src/ --type java
```

### Vulnerable patterns

| # | Pattern | Severity | Why |
|---|---------|----------|-----|
| 1 | `@GetMapping("/users/{id}")` with `@PathVariable` and no `@PreAuthorize` | High | IDOR — any authenticated user reads any user |
| 2 | `requestMatchers("/**").permitAll()` | High | Everything public |
| 3 | Manual `if (user.getRole().equals("ADMIN"))` in controller | Medium | Bypasses Spring Security audit |
| 4 | `@PathVariable Long id` without ownership check | High | IDOR on resource |
| 5 | Custom filter that does not call `chain.doFilter()` for unauthenticated | High | Bypass possible |
| 6 | `@PreAuthorize` on service but missing on REST controller | Medium | Inconsistent enforcement |

### Secure pattern (Spring Boot 3.x)

```java
// Enable method security
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig { ... }

// Controller with explicit check
@PreAuthorize("@ownershipService.canAccess(#userId, authentication.principal)")
@GetMapping("/users/{userId}")
public User getUser(@PathVariable Long userId) { ... }

// SecurityFilterChain with explicit matchers
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
        .requestMatchers("/actuator/**").hasRole("ADMIN")
        .requestMatchers("/api/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated()
    );
    return http.build();
}
```

### Mapping

- **NIST 800-82**: AC-3, AC-6
- **NIST CSF**: PR.AC-01, PR.AC-04

---

## A02:2021 — Cryptographic Failures

**Risk**: Data in transit/at rest exposed, weak hashing, hardcoded keys, TLS misconfig.

### Detection commands

```bash
# HTTP (not HTTPS) in URLs
rg -in "http://" src/main/java/ src/main/resources/ \
  | rg -v "http://(www\.)?(apache|oracle|spring|owasp|w3)\.org"

# Weak hashing
rg -in "MessageDigest\.getInstance\(\"(MD5|SHA-1|SHA1)\"\)" src/ --type java

# Hardcoded keys
rg -in "(password|secret|api[_-]?key|token)\s*[:=]\s*[\"'][A-Za-z0-9+/=]{16,}" src/ --type java

# JCE / cipher misuse
rg -in "Cipher\.getInstance\(\"(AES(/.+)?|DES(/.+)?)\"\)" src/ --type java

# Insecure random
rg -in "new Random\(\)|Math\.random\(\)" src/ --type java
```

### Vulnerable patterns

| # | Pattern | Severity | Why |
|---|---------|----------|-----|
| 1 | `DigestUtils.md5Hex(password)` | High | MD5 broken, fast hash |
| 2 | `new Random().nextInt()` for token/session | High | Predictable |
| 3 | `Cipher.getInstance("AES")` (no mode/padding) | High | ECB mode by default |
| 4 | `String secret = "my-secret-key-12345"` | Critical | Key in source |
| 5 | JDBC URL with `?useSSL=false` | High | Plaintext DB connection |
| 6 | `application.properties` with `server.ssl.enabled=false` in prod | High | TLS disabled |
| 7 | `new SecretKeySpec(password.getBytes(), "AES")` | Critical | User-controlled key |

### Secure pattern (Spring Boot 3.x)

```java
// Use BCrypt
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
}

// Use SecureRandom
SecureRandom random = new SecureRandom();
byte[] token = new byte[32];
random.nextBytes(token);

// AES-GCM with proper key
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecretKey key = new SecretKeySpec(decodeKey(), "AES");
cipher.init(Cipher.ENCRYPT_MODE, key);

// Externalize secrets
@Value("${app.jwt.secret}")
private String jwtSecret;  // from env / vault, not source
```

### Mapping

- **NIST 800-82**: SC-8, SC-13, SC-28
- **NIST CSF**: PR.DS-01, PR.DS-02

---

## A03:2021 — Injection

**Risk**: SQL/NoSQL/JPQL/OS command injection, LDAP, log injection, EL injection.

### Detection commands

```bash
# String concatenation in queries
rg -in "(createQuery|createNativeQuery|createCriteriaQuery|@Query).*\+" src/ --type java

# JPA Criteria without parameter binding
rg -in "CriteriaBuilder.*createQuery" src/ --type java

# JDBC Statement (not PreparedStatement)
rg -n "DriverManager\.getConnection|Statement\s+\w+\s*=" src/ --type java \
  | rg -v "PreparedStatement"

# ProcessBuilder / Runtime.exec with variable input
rg -n "ProcessBuilder|Runtime\.getRuntime\(\)\.exec" src/ --type java

# SpEL with user input
rg -in "ExpressionParser|SpelExpressionParser|parseExpression" src/ --type java

# JdbcTemplate with String.format
rg -in "JdbcTemplate.*format\(" src/ --type java
```

### Vulnerable patterns

| # | Pattern | Severity | Why |
|---|---------|----------|-----|
| 1 | `em.createQuery("SELECT u FROM User u WHERE u.name = '" + name + "'")` | Critical | JPQL injection |
| 2 | `@Query("SELECT * FROM users WHERE id = " + id)` | Critical | Native SQL injection |
| 3 | `Runtime.getRuntime().exec("ping " + host)` | Critical | OS command injection |
| 4 | `JdbcTemplate.queryForObject("SELECT * FROM x WHERE y = '" + v + "'", ...)` | Critical | SQL injection |
| 5 | `parser.parseExpression("T(java.lang.Runtime).getRuntime().exec('" + cmd + "')")` | Critical | SpEL injection (Spring) |
| 6 | `logger.info("User input: " + userInput)` (with CRLF in input) | Medium | Log injection / log forging |
| 7 | `String.format("SELECT * FROM x WHERE name='%s'", name)` | Critical | SQL injection via format |
| 8 | `@Query(value = "{ 'name': ?0 }", ...)` with `?0` = `{$where: ...}` (Mongo) | Critical | NoSQL injection |

### Secure pattern (Spring Boot 3.x)

```java
// Parameterized JPQL
@Query("SELECT u FROM User u WHERE u.name = :name")
User findByName(@Param("name") String name);

// Parameterized native
@Query(value = "SELECT * FROM users WHERE id = :id", nativeQuery = true)
User findById(@Param("id") Long id);

// Criteria API
CriteriaBuilder cb = em.getCriteriaBuilder();
CriteriaQuery<User> cq = cb.createQuery(User.class);
Root<User> root = cq.from(User.class);
cq.where(cb.equal(root.get("name"), cb.parameter(String.class, "name")));

// Avoid exec — use validation
// Better: refactor to a domain function. If exec is mandatory, use strict allowlist
List<String> ALLOWED = List.of("status", "ping");
if (!ALLOWED.contains(cmd)) throw new IllegalArgumentException();

// SpEL — use SimpleEvaluationContext, not StandardEvaluationContext
SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
// Never build expressions by concatenating user input

// Log injection — escape or use structured logging
log.info("User input: {}", userInput.replaceAll("[\\r\\n]", "_"));
```

### Mapping

- **NIST 800-82**: SI-10
- **NIST CSF**: PR.PS-06

---

## A04:2021 — Insecure Design

**Risk**: Missing or ineffective control design. Business logic flaws, missing rate limiting, no threat modeling.

### Detection commands

```bash
# Rate limiting presence
rg -in "RateLimiter|Bucket4j|@RateLimiter|Throttler" src/ --type java

# Business logic on critical operations
rg -in "@Transactional.*public.*(transfer|withdraw|payment|approve)" src/ --type java

# CSRF protection
rg -n "csrf\(\)\.disable" src/ --type java
```

### Vulnerable patterns

| # | Pattern | Severity | Why |
|---|---------|----------|-----|
| 1 | `http.csrf().disable()` on state-changing endpoints | High | CSRF on session-based auth |
| 2 | No rate limiting on `/login` or `/password-reset` | High | Brute force / enumeration |
| 3 | `transfer(from, to, amount)` without idempotency key | High | Duplicate transfers |
| 4 | No step-up auth for high-value operations | Medium | Privilege escalation |
| 5 | Sensitive action without audit log | Medium | No forensics trail |
| 6 | Public endpoint mutating state | High | No anti-CSRF / abuse control |
| 7 | Missing workflow approval for critical ops | Medium | Single actor, no dual control |

### Secure pattern (Spring Boot 3.x)

```java
// Keep CSRF enabled for browser sessions, use token-based auth for APIs
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .ignoringRequestMatchers("/api/**")  // only if using JWT/bearer
);

// Rate limiting with Bucket4j
@Bean
FilterRegistrationBean<RateLimitFilter> rateLimit() {
    return new FilterRegistrationBean<>(
        new RateLimitFilter(bucket4jConfig)
    );
}

// Idempotency key for financial ops
@PostMapping("/transfers")
public ResponseEntity<Transfer> create(
    @RequestHeader("Idempotency-Key") String key,
    @RequestBody TransferRequest req) { ... }
```

### Mapping

- **NIST 800-82**: PL-8, SA-3, SA-11
- **NIST CSF**: GV.RR-01, PR.PS-01

---

## A05:2021 — Security Misconfiguration

**Risk**: Default configs, exposed endpoints, verbose errors, open admin panels.

### Detection commands

```bash
# Actuator exposure
rg -n "management\.endpoints\.web\.exposure" src/main/resources/
rg -n "management\.endpoint" src/main/resources/

# CORS config
rg -in "CorsConfiguration|cors\(\)|allowedOrigins|allowedOriginPatterns" src/ --type java
rg -in "allowedOrigins.*\*" src/ --type java

# CSRF disabled
rg -n "csrf\(\)\.disable|csrf\s*->\s*\{[^}]*disable" src/ --type java

# Session fixation / cookies
rg -n "sessionCreationPolicy|cookie\.setHttpOnly|cookie\.setSecure" src/ --type java

# Debug / dev mode in prod
rg -in "spring\.profiles\.active|debug:\s*true|@Profile\(.dev.\)" src/main/resources/

# Error handling
rg -n "server\.error\.include-(message|stacktrace|exception)" src/main/resources/

# Default passwords
rg -in "(password|passwd|pwd)\s*[:=]\s*[\"'](admin|root|changeme|password|12345)[\"']" src/ --type java
```

### Vulnerable patterns

| # | Pattern | Severity | Why |
|---|---------|----------|-----|
| 1 | `management.endpoints.web.exposure.include=*` | Critical | All actuator endpoints public |
| 2 | `allowedOrigins("*")` with `allowCredentials(true)` | High | CORS + credentials = bypass |
| 3 | `server.error.include-stacktrace=always` | Medium | Stacktrace leak |
| 4 | `spring.thymeleaf.cache=false` in prod profile | Low | Performance / info leak |
| 5 | Actuator on same port as app, behind reverse proxy without auth | High | Direct exposure |
| 6 | `csrf().disable()` for non-API web app | High | CSRF |
| 7 | `Cookie cookie = new Cookie("JSESSIONID", id);` (no HttpOnly, no Secure) | Medium | Session theft via XSS |
| 8 | `spring.main.banner-mode=off` missing + custom banner with version | Low | Tech fingerprinting |
| 9 | `management.endpoint.env.enabled=true` | High | Env vars exposed via /env |

### Secure pattern (Spring Boot 3.x)

```yaml
# application-prod.yml
management:
  endpoints:
    web:
      exposure:
        include: health, info, prometheus  # NOT env, beans, heapdump
  endpoint:
    env:
      enabled: false
    heapdump:
      enabled: false
    loggers:
      enabled: false
  server:
    port: 9090  # separate port for actuator

server:
  error:
    include-message: never
    include-stacktrace: never
    include-exception: false
```

```java
// CORS — explicit allowlist, no wildcards with credentials
@Bean
CorsConfigurationSource cors() {
    CorsConfiguration c = new CorsConfiguration();
    c.setAllowedOrigins(List.of("https://app.example.com"));
    c.setAllowedMethods(List.of("GET", "POST"));
    c.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
    src.registerCorsConfiguration("/api/**", c);
    return src;
}

// Cookie security
Cookie cookie = new Cookie("SESSION", id);
cookie.setHttpOnly(true);
cookie.setSecure(true);
cookie.setSameSite(Cookie.SameSite.STRICT);
```

### Mapping

- **NIST 800-82**: CM-6, CM-7
- **NIST CSF**: PR.PS-01, PR.PS-02

---

## A06:2021 — Vulnerable and Outdated Components

**Risk**: CVEs in Spring Boot, dependencies, transitive deps (log4j, snakeyaml, jackson).

### Detection commands

```bash
# Spring Boot version
rg -n "spring-boot.version|<spring-boot" pom.xml build.gradle 2>/dev/null

# Known vulnerable libraries
rg -in "log4j-core|log4j-1\.2|snakeyaml<2\.0|jackson-databind<2\.13|commons-text<1\.10" pom.xml build.gradle

# Outdated Spring Boot 2.x
rg -n "spring-boot-starter-parent" pom.xml

# Run OWASP dependency-check
mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7 -q

# Trivy
trivy fs --severity HIGH,CRITICAL .

# Snyk
snyk test --severity-threshold=high
```

### Vulnerable patterns

| # | Pattern | Severity | Why |
|---|---------|----------|-----|
| 1 | `spring-boot-starter-parent` 2.7.x | High | EOL since Nov 2023 |
| 2 | `org.apache.logging.log4j:log4j-core` < 2.17.1 | Critical | Log4Shell (CVE-2021-44228) |
| 3 | `org.yaml:snakeyaml` < 2.0 | High | CVE-2022-1471 RCE |
| 4 | `com.fasterxml.jackson.core:jackson-databind` < 2.13.x | High | Multiple deserialization CVEs |
| 5 | `commons-text` < 1.10 | High | CVE-2022-42889 Text4Shell |
| 6 | `org.apache.tomcat.embed` < 9.0.62 | High | Multiple CVEs |
| 7 | `mysql-connector-java` < 8.0.27 | Medium | CVE-2022-21363 |
| 8 | Dependencies with `scope=compile` from unknown sources | Medium | Supply chain risk |
| 9 | Missing `dependency-check` plugin in build | Medium | No automated detection |

### Secure pattern

```xml
<!-- Use latest Spring Boot 3.x LTS -->
<parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>3.3.5</version>
</parent>

<!-- Pin versions explicitly, avoid version ranges -->
<dependency>
  <groupId>org.yaml</groupId>
  <artifactId>snakeyaml</artifactId>
  <version>2.2</version>
</dependency>
```

```xml
<!-- Add OWASP dependency-check plugin -->
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <version>9.2.0</version>
  <configuration>
    <failBuildOnCVSS>7</failBuildOnCVSS>
    <suppressionFiles>
      <suppressionFile>dependency-check-suppressions.xml</suppressionFile>
    </suppressionFiles>
  </configuration>
  <executions>
    <execution>
      <goals><goal>check</goal></goals>
    </execution>
  </executions>
</plugin>
```

### Mapping

- **NIST 800-82**: SI-2, SA-10
- **NIST CSF**: ID.AM-08, PR.PS-02

---

## A07:2021 — Identification and Authentication Failures

**Risk**: Weak passwords, no MFA, session fixation, credential stuffing, JWT misconfig.

### Detection commands

```bash
# Password policy
rg -in "passwordEncoder|BCryptPasswordEncoder|SCryptPasswordEncoder|PBKDF2" src/ --type java

# JWT
rg -in "(Jwts|jwt\.|nimbus-jose|jjwt|JWTClaimsSet)" src/ --type java
rg -n "alg.*none|Algorithm\.none" src/ --type java

# Session config
rg -n "sessionCreationPolicy|HttpSessionEventPublisher" src/ --type java

# Account lockout
rg -in "accountLocked|lockedBy|bruteForce|loginAttempt" src/ --type java

# Default credentials
rg -in "inMemoryAuthentication|withDefaultPasswordEncoder" src/ --type java
```

### Vulnerable patterns

| # | Pattern | Severity | Why |
|---|---------|----------|-----|
| 1 | `withDefaultPasswordEncoder()` | Critical | Static salt, deprecated, weak |
| 2 | `Jwts.parser().setSigningKey(key).parseClaimsJws(token)` without `requireExpiration` / `requireIssuer` | High | JWT validation gaps |
| 3 | `JwtAlgorithm.HS256` with shared secret in env (no rotation) | High | Token forgery if leaked |
| 4 | `SessionCreationPolicy.NEVER` with mutable session | Medium | Session fixation |
| 5 | No rate limiting on `/login` | High | Brute force |
| 6 | Username enumeration on `/password-reset` (different response for valid vs invalid user) | Medium | User enumeration |
| 7 | MFA not enforced for high-privilege ops | High | Privilege escalation |
| 8 | Long-lived JWT (24h+ with no refresh) | Medium | Stolen token window |
| 9 | `passwordEncoder.matches(raw, "plain")` (plaintext comparison) | Critical | Plaintext storage |

### Secure pattern (Spring Boot 3.x)

```java
// BCrypt with strong cost
@Bean
PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
}

// Spring Security 6 with proper chain
http.formLogin(form -> form.disable())
    .httpBasic(basic -> basic.disable())
    .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

// JWT validation — strict
Jws<Claims> claims = Jwts.parser()
    .verifyWith(secretKey)  // require signing
    .requireIssuer("auth.example.com")
    .requireAudience("api.example.com")
    .build()
    .parseSignedClaims(token);

// Account lockout
@EventListener
public void onFailure(AuthenticationFailureBadCredentialsEvent e) {
    userService.recordFailedLogin(e.getAuthentication().getName());
    if (userService.failedAttempts(e.getAuthentication().getName()) >= 5) {
        userService.lockAccount(e.getAuthentication().getName());
    }
}
```

### Mapping

- **NIST 800-82**: IA-2, IA-5, IA-8
- **NIST CSF**: PR.AA-01, PR.AA-03

---

## A08:2021 — Software and Data Integrity Failures

**Risk**: Insecure deserialization, missing integrity checks on updates, untrusted CI/CD.

### Detection commands

```bash
# Deserialization hotspots
rg -n "(ObjectInputStream|XMLDecoder|XStream|SnakeYaml|Yaml\(\)\.load|Serializable)" src/ --type java

# Jackson without default typing
rg -n "enableDefaultTyping|activateDefaultTyping" src/ --type java

# Auto-commit / automatic SQL DDL
rg -n "spring\.jpa\.properties\.hibernate\.hbm2ddl" src/main/resources/

# Trust of unverified downloads
rg -in "trustManager|TrustAllManager|HostnameVerifier.*true" src/ --type java
```

### Vulnerable patterns

| # | Pattern | Severity | Why |
|---|---------|----------|-----|
| 1 | `new ObjectInputStream(is).readObject()` | Critical | RCE via gadget chains |
| 2 | `new XStream().fromXML(input)` without allowlist | Critical | RCE |
| 3 | `new Yaml().load(input)` (SnakeYaml < 2.0) | Critical | RCE via constructor tags |
| 4 | `objectMapper.enableDefaultTyping()` | Critical | Polymorphic deserialization |
| 5 | `hibernate.hbm2ddl.auto=update` in prod | High | Schema mutation by attacker |
| 6 | No signature verification on plugin/extension loading | High | Malicious code execution |
| 7 | `TrustManager` that accepts all certs | High | MITM |
| 8 | `HostnameVerifier { _, _ -> true }` | High | MITM |

### Secure pattern (Spring Boot 3.x)

```java
// SnakeYaml 2.x — use SafeConstructor
Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
Map<String, Object> data = yaml.load(input);

// XStream — explicit allowlist
XStream xs = new XStream();
xs.allowTypes(new Class[]{AllowedDto.class, AnotherDto.class});
xs.denyTypes(new Class[]{java.lang.ProcessBuilder.class});

// Jackson — never enable default typing for untrusted input
ObjectMapper om = new ObjectMapper();
om.activateDefaultTyping(
    BasicPolymorphicTypeValidator.builder()
        .allowIfBaseType(MyDto.class)
        .build(),
    ObjectMapper.DefaultTyping.NON_FINAL
);

// Production: never auto-DDL
// application-prod.yml
spring.jpa.hibernate.ddl-auto: validate
```

```java
// Strict TLS
SSLContext ctx = SSLContext.getInstance("TLSv1.3");
ctx.init(null, null, null);  // use default trust store
HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
```

### Mapping

- **NIST 800-82**: SI-7, SI-10, CM-5
- **NIST CSF**: PR.DS-01, PR.PS-01

---

## A09:2021 — Security Logging and Monitoring Failures

**Risk**: No audit trail, no alerting on suspicious events, logs not centrally stored.

### Detection commands

```bash
# Logging framework
rg -n "private static final Logger|@Slf4j|LoggerFactory\.getLogger" src/ --type java

# Sensitive data in logs
rg -in "log\.(info|debug|trace).*\b(password|secret|token|ssn|creditCard|cvv)\b" src/ --type java
rg -in "logger\.(info|debug).*request" src/ --type java

# Audit events
rg -n "AuditEvent|@EventListener.*AuthenticationSuccess|AuthenticationFailure" src/ --type java

# Missing logback config
ls src/main/resources/logback*.xml 2>/dev/null
```

### Vulnerable patterns

| # | Pattern | Severity | Why |
|---|---------|----------|-----|
| 1 | Login attempts not logged | High | No brute-force detection |
| 2 | Privilege changes not logged | High | No audit trail |
| 3 | `log.info("Request: " + request)` (whole payload) | Medium | PII / secret leak to logs |
| 4 | No log correlation ID | Medium | Hard to trace incidents |
| 5 | Logs not sent to SIEM | Medium | Blind to attacks |
| 6 | Logs not protected from tampering (mutable path) | Medium | Attacker deletes evidence |
| 7 | Sensitive fields logged at DEBUG in prod | High | PII exposure if DEBUG enabled |
| 8 | No alerting on 4xx/5xx spikes | Medium | Slow incident response |

### Secure pattern (Spring Boot 3.x)

```java
// Audit event listener
@Component
@Slf4j
public class SecurityAuditListener {
    @EventListener
    public void onSuccess(AuthenticationSuccessEvent e) {
        AuditEvent evt = new AuditEvent(
            Instant.now(), e.getAuthentication().getName(),
            "LOGIN_SUCCESS", Map.of("ip", request.getRemoteAddr())
        );
        auditPublisher.publish(evt);
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent e) {
        log.warn("LOGIN_FAILURE user={} reason={}",
            e.getAuthentication().getName(), e.getException().getMessage());
    }
}

// Structured logging with correlation ID
MDC.put("correlationId", UUID.randomUUID().toString());
try {
    // handle request
} finally {
    MDC.remove("correlationId");
}
```

```xml
<!-- logback-spring.xml: no secrets, async, JSON for SIEM -->
<configuration>
  <appender name="JSON" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
    <file>/var/log/app/app.json</file>
  </appender>
  <root level="INFO">
    <appender-ref ref="JSON"/>
  </root>
</configuration>
```

### Mapping

- **NIST 800-82**: AU-2, AU-3, AU-6, AU-12
- **NIST CSF**: DE.CM-01, DE.AE-02

---

## A10:2021 — Server-Side Request Forgery (SSRF)

**Risk**: Attacker forces server to make requests to internal resources, cloud metadata, or arbitrary external URLs.

### Detection commands

```bash
# HTTP clients with user-controlled URL
rg -in "(RestTemplate|WebClient|HttpClient|URLConnection|URI\.create|new URL\()" src/ --type java

# URL building from request data
rg -in "redirect|forward|fetch|proxy" src/ --type java \
  | rg -i "(http|param|input|user)"

# Image / file fetch from URL
rg -in "(fetchImage|downloadFile|proxyUrl|imageUrl|avatarUrl)" src/ --type java
```

### Vulnerable patterns

| # | Pattern | Severity | Why |
|---|---------|----------|-----|
| 1 | `new URL(userInput).openStream()` | High | SSRF |
| 2 | `restTemplate.getForObject(userUrl, ...)` | High | SSRF |
| 3 | `webClient.get().uri(userUrl)` | High | SSRF |
| 4 | `redirectAttributes.addAttribute("url", userUrl)` then 302 | High | Open redirect + SSRF |
| 5 | Image proxy `GET /proxy?url=...` returning server-fetched content | High | SSRF |
| 6 | Webhook target with user-supplied URL | High | SSRF callback |
| 7 | `URI.create(userInput)` to internal services without validation | Critical | Internal pivot |

### Secure pattern (Spring Boot 3.x)

```java
// URL allowlist + DNS resolution check
private static final Set<String> ALLOWED_HOSTS = Set.of(
    "api.trusted.com", "cdn.trusted.com"
);

public URI safeUri(String input) throws URISyntaxException {
    URI uri = new URI(input);
    String host = uri.getHost();
    if (host == null) throw new IllegalArgumentException("no host");
    InetAddress addr = InetAddress.getByName(host);
    if (addr.isAnyLocalAddress() || addr.isLoopbackAddress()
        || addr.isSiteLocalAddress() || addr.isMulticastAddress()) {
        throw new IllegalArgumentException("internal address not allowed");
    }
    if (!ALLOWED_HOSTS.contains(host.toLowerCase())) {
        throw new IllegalArgumentException("host not in allowlist");
    }
    return uri;
}

// RestTemplate with strict validation
@PostMapping("/webhook")
public Response handle(@RequestBody WebhookRequest req) {
    URI safe = safeUri(req.getTarget());
    return restTemplate.postForObject(safe, req.getPayload(), Response.class);
}
```

### Mapping

- **NIST 800-82**: SC-7, SC-8
- **NIST CSF**: PR.PS-06

---

## Severity Mapping Summary

| OWASP | Critical | High | Medium | Low |
|-------|----------|------|--------|-----|
| A01 Broken Access Control | 0 | 3 | 2 | 1 |
| A02 Cryptographic Failures | 3 | 3 | 1 | 0 |
| A03 Injection | 6 | 1 | 1 | 0 |
| A04 Insecure Design | 0 | 3 | 3 | 1 |
| A05 Security Misconfiguration | 1 | 3 | 4 | 2 |
| A06 Vulnerable Components | 1 | 4 | 4 | 0 |
| A07 Auth Failures | 2 | 4 | 2 | 1 |
| A08 Data Integrity | 4 | 2 | 1 | 1 |
| A09 Logging Failures | 0 | 2 | 5 | 1 |
| A10 SSRF | 1 | 5 | 1 | 0 |
| **Total per severity** | **18** | **30** | **24** | **7** |

(Indicative — actual counts depend on codebase)

## References

- OWASP Top 10 2021: https://owasp.org/Top10/
- Spring Security 6: https://docs.spring.io/spring-security/reference/
- Spring Boot 3 reference: https://docs.spring.io/spring-boot/docs/3.x/reference/
- CWE catalog: https://cwe.mitre.org/
