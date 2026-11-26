# Pulumi Stack & Policy Viewer for VS Code

Inspect `Pulumi.yaml`, `Pulumi.yml`, `Pulumi.*.yaml` and `Pulumi.*.yml` files in VS Code without running the Pulumi CLI or making cloud calls. Multi-environment Pulumi repositories mix project manifests, runtime options, backend URLs, encrypted `secure:` secrets and dozens of provider config keys across files where plaintext passwords, missing `secretsprovider` settings or hardcoded cloud keys are easy to miss in raw YAML. This extension parses Pulumi project and stack files locally in plain JavaScript with zero CLI or network calls.

![Pulumi Stack & Policy Viewer showing project metadata, masked secure config keys and static secret-hygiene findings](images/screenshot.png)

## What it opens

- `Pulumi.yaml`, `Pulumi.yml`, `Pulumi.*.yaml` and `Pulumi.*.yml` files.
- Any open Pulumi project or stack YAML file via the Command Palette or Explorer context menu (Open in Pulumi Stack & Policy Viewer).
- Nothing to install, no Pulumi CLI required, no cloud or network calls.

## The free part

- Project, runtime and backend metadata viewer: surfaces project name, runtime, toolchain options, backend URL, `secretsprovider`, `encryptionsalt` and plugin declarations on one screen.
- Stack config key/value table: groups keys by namespace (such as `aws`, `gcp`, `azure-native` or your app namespace), flags encrypted `secure:` values and masks ciphertext cleanly.
- Static security findings: flags plaintext secrets in stack YAML (secret, password, token, API key or credential keys without a `secure:` wrapper), missing `secretsprovider`, hardcoded AWS/GCP/Azure tokens, and unpinned runtime or plugin versions (`latest` or `*`).

## The Pro tools, with 1 free try

Pro adds the audit, diff and export steps: generate a Markdown stack secret-hygiene and config audit for one file or a folder, compare two `Pulumi.<env>.yaml` stack files (such as dev vs prod) in Markdown for config and secret-posture changes, or export a Markdown and CSV redacted stack configuration inventory locally. Your first try of each Pro tool is free. Zovo Pro is USD 19 once, and the team licence is USD 59.

## Why not plain text

Reading a 200-line `Pulumi.prod.yaml` file as raw YAML makes it easy to overlook one unencrypted `dbPassword` key tucked between encrypted `secure:` entries or a missing `secretsprovider`. A local viewer puts namespaces, secret posture and static findings on one screen.

## More tools by Zovo

See full docs and install options at [vscode.zovo.one/extensions/zovo-pulumi-viewer/](https://vscode.zovo.one/extensions/zovo-pulumi-viewer/), browse all Zovo VS Code extensions at [vscode.zovo.one](https://vscode.zovo.one/), or explore [Zovo Pro](https://vscode.zovo.one/pro/).
