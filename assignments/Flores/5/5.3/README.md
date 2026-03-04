
# 5.3: CSP Embedding Demonstration

This directory demonstrates the use of Content Security Policy (CSP) headers to control the embedding of external content using iframes. The example tests embedding [Dailymotion](https://www.dailymotion.com) and shows how to block or allow its content based on CSP configuration. The CSP settings can be toggled dynamically using an environment variable.

## Files

- **`server.js`**: A Node.js server that serves the `embed.html` file and sets the CSP headers to allow or block iframe embedding based on the `ENABLE_EMBEDDING` environment variable.

---

## Setup Instructions

1. **Install Dependencies**:

   Ensure you have Node.js installed. Then, install the required dependencies by running:

   ```bash
   npm install express
   ```

2. **Run the Server**:

   Start the server by running:

   ```bash
   # To start the server with embedding enabled:
   ENABLE_EMBEDDING=true node server.js

   # Or to start the server with embedding disabled:
   ENABLE_EMBEDDING=false node server.js
   ```

3. **Access the Test Page**:

   Open your browser and navigate to:

   [http://localhost:4000/embed.html](http://localhost:4000/embed.html)

---

## CSP Configurations

### Toggling Embedding Using Environment Variable

The server reads the `ENABLE_EMBEDDING` environment variable to determine the CSP configuration:

- **Embedding Enabled (`ENABLE_EMBEDDING=true`)**:

  In `server.js`, when `ENABLE_EMBEDDING` is set to `'true'`, the CSP directive is set to:

  ```http
  Content-Security-Policy: frame-src 'self' https://www.dailymotion.com
  ```

  **Observed Behavior**:

  - The iframe successfully loads the Dailymotion content.
  - No CSP violation errors appear in the browser console.

- **Embedding Disabled (`ENABLE_EMBEDDING=false`)**:

  When `ENABLE_EMBEDDING` is not set or set to any value other than `'true'`, the CSP directive is set to:

  ```http
  Content-Security-Policy: frame-src 'none'
  ```

  **Observed Behavior**:

  - The iframe remains blank or shows an error message.
  - The browser console shows a CSP violation error.

  **Example Error in Browser Console**:

  ```
  Refused to frame 'https://www.dailymotion.com/' because it violates the following Content Security Policy directive: "frame-src 'none'".
  ```

---

## Explanation

By using the `ENABLE_EMBEDDING` environment variable, we can dynamically toggle the CSP settings without changing the code. This demonstrates how CSP can be used to control which external resources can be embedded in your web pages.

- **Content Security Policy (CSP)**:

  CSP is a security standard that helps prevent cross-site scripting (XSS), clickjacking, and other code injection attacks resulting from the execution of malicious content in the trusted web page context.

- **CSP Directives Used**:

  - `frame-src 'self' https://www.dailymotion.com`: Allows embedding content from the same origin (`'self'`) and from `https://www.dailymotion.com`.
  - `frame-src 'none'`: Disallows all embedding in frames or iframes.

---

## Additional Notes

- **Environment Variables**:

  Environment variables can be set in different ways depending on your operating system and shell. For example:

  - On Unix/Linux/macOS:

    ```bash
    ENABLE_EMBEDDING=true node server.js
    ```

  - On Windows Command Prompt:

    ```cmd
    set ENABLE_EMBEDDING=true
    node server.js
    ```

  - On Windows PowerShell:

    ```powershell
    $env:ENABLE_EMBEDDING="true"
    node server.js
    ```

- **Testing CSP Violations**:

  - Open the browser's developer tools (usually by pressing `F12`).
  - Go to the "Console" tab to see CSP violation errors.
  - Refresh the page after changing the CSP configuration to see the updated behavior.

- **Browser Compatibility**:

  CSP is supported by all modern browsers, but the exact behavior might vary slightly between browsers.

---

## Conclusion

This example illustrates how to use CSP headers to control the embedding of external content and how to dynamically change the CSP configuration using environment variables. By carefully configuring CSP policies, developers can enhance the security of their web applications.
