# xs_leak_oracle_detector

A Burp Suite extension for probing and identifying potential cross-site leak (XS-Leak) oracles by comparing the same HTTP endpoint under different identity/user states.

This extension is designed for use in Burp's legacy Jython environment and helps automate a common differential testing workflow: replay a target request with different identity-related headers and look for timing or response differences that suggest state-dependent behavior.

## What it does

- Captures observed in-scope HTTP traffic from Burp
- Lets you set a target request to replay
- Lets you capture multiple user/state variants in memory
- Replays the target request using selected identity headers from each captured state
- Compares timing, redirect behavior, status, body length, and security headers
- Flags suspicious differential behavior as a candidate XS-Leak oracle

## Key features

- Context-menu actions to set a target request and capture user/state samples
- In-memory role/state capture for multiple identities or browser states
- Configurable identity headers (comma-separated)
- Adjustable replay rounds
- Timing threshold for signaling differences
- Comparison table with differential signals and detailed assessment notes
- Safety checks for Burp scope, same-origin validation, and non-GET/HEAD replay warnings

## Requirements

- Burp Suite
- Burp's Jython support for Java-based extensions
- A target application in Burp scope

## Installation

1. Open Burp Suite.
2. Go to Extender > Extensions.
3. Add the extension using the Python/Jython loader supported by your Burp version.
4. Load `xs_leak_oracle_detector.py`.
5. The extension will add a new tab named `XS-Leak Oracles`.

## Usage

### 1. Target a request

Use the Burp message editor context menu and choose:

- `Set request as XS-Leak comparison target`

This loads the selected HTTP request as the target replay endpoint.

### 2. Capture identity states

From a request in Burp, choose:

- `Capture request as XS-Leak user/state`

You can name each captured state (for example, `Alice`, `Bob`, `logged in`, `anonymous`) and the extension will store the request and origin for later comparison.

### 3. Configure the comparison

In the extension panel:

- Set `Identity headers` to the headers that represent user or state identity for your target (for example: `Cookie, Authorization, X-CSRF-Token`)
- Set the number of rounds to replay
- Optionally enable `Allow non-GET/HEAD replay` if you intentionally want to replay unsafe methods

### 4. Compare captured states

1. Select the target request in the extension UI.
2. Select at least two captured states.
3. Click `Compare selected roles`.
4. Review the result table for timing or header differences.

## Interpretation

The extension reports differential indicators, not proof of browser exploitability.

A result is treated as a candidate oracle when the compared state variants differ in one or more of the following:

- Timing delta
- HTTP status
- Response body length
- Redirect behavior
- Security headers such as `cache-control`, `x-frame-options`, `cross-origin-opener-policy`, `cross-origin-resource-policy`, `vary`, or `location`

These signals may indicate that the application leaks state across origins or contexts, but they still require careful browser-based confirmation.

## Important notes

- The detector only compares requests within the same origin and Burp scope.
- Non-GET/HEAD replay is blocked by default to reduce risk.
- The tool is intended for authorized security testing in environments where you have explicit permission.
- Differential data can be useful for identifying candidate side channels, but should not be treated as definitive exploitability without further validation.

## Repository files

- `xs_leak_oracle_detector.py` — main Burp extension implementation
- `README.md` — project documentation

## License

This repository does not currently declare a license in the visible project files. If you plan to distribute or reuse the code, check whether a license is required or added by the project owner before publication or commercial use.
