# Security Vulnerability Report for Movie Ticket Booking Application

This document outlines the security vulnerabilities identified in the provided Flask application code. Understanding these vulnerabilities is crucial for improving the application's security posture.

## Vulnerabilities

**1. A02:2021 Cryptographic Failures (formerly A07:2017 Broken Authentication)**

* **Description:** The login function provides informative error messages that distinguish between invalid usernames and incorrect passwords for valid usernames, allowing for username enumeration.
* **Exploitation:** Attackers can use this information to build a list of valid usernames, reducing the complexity of brute-force password attacks.

Run the bruteforce.py file 

* **Location:** `/login` route.
* **Mitigation:** Implement a generic "Invalid username or password" error message for all login failures. Employ rate limiting and account lockout mechanisms.

**2. A04:2021 Insecure Design (Insecure Deserialization)**

* **Description:** User profile data is serialized using `pickle` and stored in a cookie. Deserialization using `pickle.loads()` is inherently unsafe with untrusted data.
* **Exploitation:** Attackers can craft malicious pickled objects within the cookie to achieve remote code execution on the server.

Run payload.py

curl -H "Cookie: profile_data=gASVcgAAAAAAAACMCF9fbWFpbl9flIwMZGlzcGxheV9kYXRhlJOUfZQojARuYW1llIwNSW5qZWN0ZWQgTmFtZZSMBWVtYWlslIwUaW5qZWN0ZWRAZXhhbXBsZS5jb22UjARyb2xllIwNSW5qZWN0ZWQgUm9sZZR1hZRSlC4=" http://192.168.1.7:5000/profile

* **Location:** `/profile` and `/set_profile` routes.
* **Mitigation:** Avoid using `pickle` for storing data in cookies. Use secure serialization formats like JSON with proper signing (e.g., using Flask-Session).

**3. A03:2021 Injection (Command Injection)**

* **Description:** Potential for command injection through user-provided filenames during review uploads and potentially when viewing files due to insufficient sanitization and potential path traversal.
* **Exploitation:** Attackers might be able to execute arbitrary system commands or access sensitive files on the server.

http://127.0.0.1:5000/view_file/password.txt

THis would spit all the password



* **Location:** `/upload_review` and `/view_file/<path:filename>` routes.
* **Mitigation:** Implement robust filename sanitization and validation. Consider using internally generated unique filenames. Strictly validate and sanitize the `filename` parameter in the `/view_file` route to prevent path traversal.

**4. A01:2021 Broken Access Control (Unrestricted File Upload & Access)**

* **Description:** The application allows uploading any file type without proper validation, and the `/view_file` route lacks adequate access controls.
* **Exploitation:** Attackers can upload malicious files (e.g., web shells) and potentially access them or other sensitive files on the server.
* **Location:** `/upload_review` and `/view_file/<path:filename>` routes.

you can upload any files and show the files
http://127.0.0.1:5000/view_file/webshell.py


* **Mitigation:** Implement strict server-side file type validation. Store uploaded files in a secure location not directly accessible by the web server.

**5. A03:2021 Injection (Simulated SQL Injection)**

* **Description:** While SQLAlchemy is used, the construction of the search query with `ilike` using f-strings could theoretically pose a risk if not handled with extreme care or if underlying components have vulnerabilities.
* **Exploitation:** Attackers might attempt to inject SQL code through the search query parameter.

' OR 1=1 --'

* **Location:** `/search_results` route.
* **Mitigation:** Continue using SQLAlchemy's parameterized query methods and avoid string formatting for building SQL queries with user input.


**7. A03:2021 Injection (Server-Side Template Injection - SSTI)**

* **Description:** Potential for SSTI if user-controlled data (filenames or file content) is directly rendered in Jinja2 templates without proper escaping.
* **Exploitation:** Attackers could inject malicious Jinja2 template expressions to execute arbitrary code or disclose sensitive information on the server.
* **Location:** `/movie/<int:movie_id>/reviews/<filename>` route and templates.
* **Mitigation:** Always ensure proper escaping of user-controlled data when rendering it in HTML templates.

http://192.168.1.7:5000/movie/3/reviews/payload.py

 
**9. A07:2017 Cross-Site Scripting (XSS) - Reflected (Potential)**

* **Description:** Potential for XSS if user-provided data in search results, filenames, or file content is rendered in HTML without proper escaping.
* **Exploitation:** Attackers could inject malicious JavaScript code that gets executed in other users' browsers.

"><script>alert(1);</script><"

 
* **Location:** `/search_results`, `/view_file_content`, `/view_review_content` templates.
* **Mitigation:** Ensure all user-provided data rendered in HTML templates is properly escaped.

## Recommendations

It is strongly recommended to address these vulnerabilities to secure the Movie Ticket Booking application. The mitigations suggested for each vulnerability should be implemented promptly. Further security best practices, such as regular security audits and keeping dependencies up-to-date, should also be followed.