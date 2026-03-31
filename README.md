# IAM Policy Auditor

This tool helps you audit your AWS IAM roles to identify overly permissive policies that could pose a security risk to your account.

1. Make sure you have your AWS credentials configured (e.g., via `aws configure` or environment variables).
2. Run the script from your terminal:
   ```bash
   python Q2.py
   ```
3. Follow the on-screen menu:
   - **Option 1**: Scan every IAM role in your AWS account. You will need to provide your Account ID for verification.
   - **Option 2**: Scan one specific IAM role by entering its name.


The script checks for common security misconfigurations, such as:
- Policies that grant full administrative access (`AdministratorAccess` or `Admin`).
- Use of wildcards (`*`) in Actions or Resources, which can be too permissive.
- High-risk permissions like `iam:PassRole` when paired with broad resource access.

If any risky statements are found, the tool will alert you and suggest best practices for adhering to the principle of least privilege.
