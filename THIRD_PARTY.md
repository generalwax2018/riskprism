# Third-party code

RiskPrism uses the Python standard library only. One file is copied in from another project:

| File | Project | License |
|---|---|---|
| `qrcodegen.py` | [QR Code generator library](https://www.nayuki.io/page/qr-code-generator-library), Project Nayuki | MIT (notice kept at the top of the file) |

It draws the QR code on the account setup page, so authenticator apps can be added without sending the secret to an outside service.
