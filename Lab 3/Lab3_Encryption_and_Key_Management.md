# IKB42603 Cloud Computing Security Essentials

## Lab 3: Encryption and Key Management

**Student:** Muhamad Izzat A'kif Bin Mohd Sanusi
**Student ID:** 52215124688  
**Date:** 29 August 2026  
**Environment:** Kali Linux, OpenSSL, Docker, AWS CLI v2, LocalStack KMS

## 1. Objectives

This lab demonstrates symmetric and asymmetric cryptography, digital signatures, TLS protection for data in transit, KMS-based key management, envelope encryption, per-tenant key separation, cryptographic erasure, hashing, and tamper-evident hash chains.

## 2. Session A — Encryption Fundamentals

### Task 1 — Symmetric Encryption (Data at Rest)

#### Step 1: Create a sensitive record

```bash
mkdir -p ~/IKB42603-Lab3
cd ~/IKB42603-Lab3
echo 'Patient: alipp, Diagnosis: confidential' > record.txt
cat record.txt
```

The command created `record.txt` and displayed the sample patient record.

![Task 1 - sensitive record created](lab-images/lab3/z1.png)

#### Step 2: Encrypt the record with AES-256-CBC

```bash
openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc
```

OpenSSL requested and confirmed a passphrase. The passphrase is not displayed or stored in this report.

![Task 1 - AES encryption](lab-images/lab3/z2.png)

#### Step 3: Demonstrate that the encrypted file is unreadable

```bash
cat record.enc
```

The terminal displayed binary-looking content instead of the original plaintext, confirming that the file was not human-readable.

![Task 1 - unreadable ciphertext](lab-images/lab3/z3.png)

#### Step 4: Decrypt and verify the record

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt
diff record.txt record.dec.txt && echo 'MATCH: decryption successful'
```

**Observed result:** `MATCH: decryption successful`

![Task 1 - successful decryption comparison](lab-images/lab3/z4.png)

#### Task 1 report question

The key-distribution problem is that every authorized sender and receiver must obtain the same secret key without an attacker intercepting it. The key must then be stored, rotated, revoked, and protected by every party. In a cloud environment, many users, services, regions, and tenants may require access, so copying a shared secret increases the attack surface and makes separation of duties and revocation difficult. A centralized KMS reduces this risk by controlling key use and access without distributing master-key material to applications.

### Task 2 — Asymmetric Encryption and Digital Signatures

#### Step 1: Generate the RSA private key

```bash
openssl genrsa -out private.pem 2048
```

The evidence shows a 2048-bit RSA private key file was created.

![Task 2 - RSA private key generated](lab-images/lab3/z5.png)

#### Step 2: Derive the public key

```bash
openssl rsa -in private.pem -pubout -out public.pem
```

The public key was successfully written to `public.pem`.

![Task 2 - public key generated](lab-images/lab3/z6.png)

#### Step 3: Encrypt with the public key

```bash
openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa
```

The encrypted RSA output file was created.

![Task 2 - RSA public-key encryption](lab-images/lab3/z7.png)

#### Step 4: Decrypt with the private key and compare

```bash
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt
diff record.txt record.rsa.txt && echo 'MATCH: RSA decryption successful'
```

**Observed result:** `MATCH: RSA decryption successful`

![Task 2 - RSA private-key decryption](lab-images/lab3/z8.png)

#### Step 5: Sign the record

```bash
openssl dgst -sha256 -sign private.pem -out record.sig record.txt
```

The evidence shows that `record.sig` was created.

![Task 2 - digital signature created](lab-images/lab3/z9.png)

#### Step 6: Verify the signature

```bash
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

**Observed result:** `Verified OK`

![Task 2 - signature verified](lab-images/lab3/z11.png)

The public key is used to encrypt data for the private-key owner, while the private key is used to decrypt it. For signatures, the private key signs and the public key verifies. The verified signature demonstrates origin authentication and integrity, assuming the private key remained under the signer’s control.

### Task 3 — Encryption in Transit (TLS)

#### Step 1: Generate a self-signed certificate

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 7 -nodes -subj '/CN=localhost'
```

The evidence shows that `cert.pem` and `key.pem` were created. The private key itself is not reproduced.

![Task 3 - certificate and TLS key generated](lab-images/lab3/z10.png)

#### Step 2: Start the HTTPS service

The submitted evidence used an Nginx Alpine container, a custom `nginx-tls.conf`, read-only certificate/key mounts, and port `8443` mapped to container port `443`:

```bash
docker run --rm -d --name tls -p 8443:443 \
  -v "$(pwd)/nginx-tls.conf:/etc/nginx/nginx.conf:ro" \
  -v "$(pwd)/cert.pem:/etc/nginx/cert.pem:ro" \
  -v "$(pwd)/key.pem:/etc/nginx/key.pem:ro" \
  -v "$(pwd)/record.txt:/usr/share/nginx/html/record.txt:ro" \
  nginx:alpine
docker ps --filter name=tls
```

The container status was `Up`, and port `8443` was mapped to HTTPS port `443`.

![Task 3 - TLS container running](lab-images/lab3/z12.png)

#### Step 3: Connect over TLS

Required command:

```bash
curl -k https://localhost:8443/record.txt
```

**Evidence status:** Complete. The submitted screenshot shows the HTTPS command and its successful response.

**Observed result:** `Patient: alipp, Diagnosis: confidential`

![Task 3 - successful HTTPS request over TLS](lab-images/lab3/aaa.png)

TLS encrypts the traffic between client and server so an on-path observer cannot directly read the record. The `-k` option is acceptable for this local exercise because the certificate is self-signed, but it disables certificate trust validation and must not be normal production practice.

## 3. Session B — KMS, Envelope Encryption, and Erasure

The LocalStack endpoint used throughout was:

```bash
EP='--endpoint-url=http://localhost:4566'
```

### Task 4 — Create and Use a KMS Master Key

#### Step 1: Create the tenant A customer-managed key

```bash
aws $EP kms create-key --description 'CCSE tenant-A master key'
KEY_A='[REDACTED]'
```

**Observed status:** A tenant A key existed and was successfully used by the later KMS operations. However, the submitted screenshots do not include the original tenant A `create-key` response. The complete Key ID and ARN are intentionally omitted.

#### Step 2: Encrypt a small secret directly with KMS

```bash
aws $EP kms encrypt --key-id "$KEY_A" \
  --plaintext "$(echo -n 'hello' | base64)" \
  --query CiphertextBlob --output text
```

**Observed result:** KMS returned a ciphertext blob. Its value is `[REDACTED]` because it is secret-bearing encrypted material. The original evidence is `z13.png`, which is deliberately not embedded to avoid reproducing the ciphertext.

### Task 5 — Envelope Encryption

#### Step 1: Generate an AES-256 data key

```bash
DATAKEYS=$(aws $EP kms generate-data-key --key-id "$KEY_A" \
  --key-spec AES_256 --query '[Plaintext,CiphertextBlob]' --output text)
echo "$DATAKEYS" | awk '{print $1}' > datakey.b64
echo "$DATAKEYS" | awk '{print $2}' | base64 -d > datakey.enc
unset DATAKEYS
```

The plaintext and wrapped data-key values are not included. The evidence shows `datakey.b64` and `datakey.enc` were created, but is not embedded because the terminal command handles secret material.

#### Step 2: Decode the plaintext data key and encrypt locally

```bash
base64 -d datakey.b64 > datakey.bin
openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc \
  -pass file:./datakey.bin
```

The evidence shows that the 32-byte plaintext data key and encrypted record were created.

![Task 5 - local envelope encryption](lab-images/lab3/z15.png)

#### Step 3: Delete plaintext data-key copies

```bash
rm datakey.bin datakey.b64
if [ ! -e datakey.bin ] && [ ! -e datakey.b64 ]; then
  echo 'Plaintext data key deleted'
fi
ls -l datakey.enc record.env.enc
```

**Observed result:** `Plaintext data key deleted`. Only the wrapped key and encrypted data remained.

![Task 5 - plaintext data key removed](lab-images/lab3/z16.png)

#### Additional validation: unwrap and decrypt before erasure

Before disabling tenant A’s master key, the wrapped data key was recovered through KMS, used to decrypt the file, and compared with the original:

```bash
aws $EP kms decrypt --key-id "$KEY_A" \
  --ciphertext-blob fileb://datakey.enc \
  --query Plaintext --output text > recovered-datakey.b64
base64 -d recovered-datakey.b64 > recovered-datakey.bin
openssl enc -d -aes-256-cbc -pbkdf2 -in record.env.enc \
  -out record.env.dec.txt -pass file:./recovered-datakey.bin
diff record.txt record.env.dec.txt && echo 'MATCH: envelope decryption successful'
```

**Observed result:** `MATCH: envelope decryption successful`

![Task 5 - successful envelope decryption](lab-images/lab3/34.png)

The temporary recovered plaintext key files were subsequently deleted, as shown in the Task 6 evidence.

### Task 6 — Per-Tenant Keys and Cryptographic Erasure

#### Step 1: Create a separate key for tenant B

```bash
KEY_B=$(aws $EP kms create-key --description 'CCSE tenant-B master key' \
  --query 'KeyMetadata.KeyId' --output text)
```

**Observed status:** A distinct tenant B Key ID was returned. Both tenant Key IDs are `[REDACTED]`. The original screenshot (`2.png`) is not embedded because it displays the complete identifiers.

#### Step 2: Confirm tenant isolation

```bash
aws $EP kms decrypt --key-id "$KEY_B" \
  --ciphertext-blob fileb://datakey.enc 2>&1 | head -3
```

**Observed result:** `IncorrectKeyException`. Tenant B’s key could not unwrap a data key protected by tenant A’s key.

![Task 6 - cross-tenant decryption rejected](lab-images/lab3/3.png)

#### Step 3: Schedule deletion of tenant A’s key

```bash
aws $EP kms schedule-key-deletion --key-id "$KEY_A" \
  --pending-window-in-days 7
```

**Observed result:** The key state changed to `PendingDeletion` with a seven-day window. The complete Key ID and deletion timestamp are omitted from this report.

#### Step 4: Disable tenant A’s key immediately

```bash
rm recovered-datakey.bin recovered-datakey.b64
aws $EP kms disable-key --key-id "$KEY_A"
aws $EP kms describe-key --key-id "$KEY_A" \
  --query 'KeyMetadata.KeyState' --output text
```

**Observed result:** `Disabled`

#### Step 5: Attempt to unwrap the data key after erasure

```bash
aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc 2>&1 | head -3
```

**Observed result:** `DisabledException` — KMS refused to decrypt because tenant A’s key was disabled. The complete ARN in the original error is `[REDACTED]` and the screenshot is not embedded.

This demonstrates immediate logical cryptographic erasure. Scheduled deletion provides eventual permanent destruction after the waiting period. Until permanent deletion occurs, an authorized administrator may be able to cancel deletion or re-enable the key; therefore, the lab’s disabled state is a simulation of erasure rather than irreversible deletion at the moment the screenshot was taken.

### Task 7 — Integrity and Tamper-Evidence

#### Step 1: Hash the original file, tamper with a copy, and compare

```bash
cp record.txt tampered.txt
echo 'x' >> tampered.txt
sha256sum record.txt tampered.txt
```

**Observed hashes:**

```text
14394cdbe2b95a99ef264e698b21872787f2b29643d52d1571ef82e0f6617460  record.txt
da6d4a08d1e1fa61be8cde7f57e1646f216bb29332acda7392687acf8c00e8b3  tampered.txt
```

The hashes differ, showing that even a small content change is detectable.

![Task 7 - differing SHA-256 hashes](lab-images/lab3/44.png)

#### Step 2: Build a hash chain

```bash
PREV=0
for line in 'login ok' 'file read' 'export data'; do
  PREV=$(echo -n "$PREV$line" | sha256sum | cut -d' ' -f1)
  echo "$line | $PREV"
done
```

**Observed chain:**

```text
login ok   | 573f9af26d45d395a1089ef5fec4d50ccddc17c0ea4269c2c91d90929a820053
file read  | 6c3adc61ece69412b338e43d761435e95dbfc948253f8f600087b0a4c5ad2d3d
export data| e1470ccfaf43dcab3c17d5710dc9eacbb7ac65c9f522ca98c2c503431b32da68
```

![Task 7 - tamper-evident hash chain](lab-images/lab3/55.png)

## 4. Short-Answer Questions

### Q1. Compare symmetric and asymmetric encryption: speed, key distribution, and typical use.

Symmetric encryption uses one shared secret for encryption and decryption. It is fast and efficient for large files, disks, databases, and network-session data, but securely distributing the shared key is difficult. Asymmetric encryption uses a public/private key pair. It is slower and has data-size limitations, but the public key can be widely distributed without revealing the private key. It is typically used for identity, digital signatures, secure key exchange, and encrypting small secrets or symmetric data keys. Practical systems such as TLS combine both: asymmetric cryptography authenticates or establishes a session key, and symmetric cryptography protects the bulk traffic.

### Q2. Why is key management described as the weakest link, not the algorithm?

Modern algorithms such as AES-256 and correctly sized RSA are computationally strong when used properly. Failures more commonly occur because keys are exposed in source code or logs, copied insecurely, granted to excessive identities, never rotated, poorly backed up, or not revoked after compromise. If an attacker obtains the key, the strength of the algorithm no longer protects the data. Secure generation, storage, access control, auditing, rotation, recovery, and destruction are therefore the decisive controls.

### Q3. Explain envelope encryption and why only the master key needs hardware-grade protection.

Envelope encryption uses a randomly generated data-encryption key (DEK) to encrypt the actual data locally. KMS then encrypts, or wraps, that DEK using a master key/key-encryption key (KEK). The application stores the ciphertext together with only the wrapped DEK. To decrypt, it asks KMS to unwrap the DEK, uses the plaintext DEK briefly, and removes it from memory or disk. The master key never needs to leave KMS or an HSM. Hardware-grade protection is concentrated on this small master key because the bulk data and many DEKs can remain outside the HSM in encrypted form, making the design scalable and economical.

### Q4. How does cryptographic erasure achieve provable deletion where overwriting cannot in the cloud?

Cloud data can have replicas, snapshots, backups, remapped storage blocks, and provider-managed copies, so a tenant often cannot verify that every physical copy was overwritten. With cryptographic erasure, all copies remain encrypted and the controlling key is securely destroyed. Without that key, the ciphertext is computationally unrecoverable even if copies remain. Per-tenant or per-object keys narrow the deletion scope and allow deletion to be demonstrated through key state and audit records. Disabling a key is reversible; final key destruction is what makes deletion permanent.

### Q5. How does a hash chain make a log tamper-evident?

Each log entry’s hash includes the previous entry’s hash and the current entry’s data. Changing, removing, inserting, or reordering an earlier event changes its hash and therefore invalidates every later link. A verifier recomputes the sequence and compares the final trusted checkpoint. A hash chain is tamper-evident, not automatically tamper-proof: an attacker who can rewrite the entire log could recompute the chain. The latest hash should therefore be signed, timestamped, or stored in a separate protected system.

## 5. Verification Commands

```bash
aws --endpoint-url=http://localhost:4566 kms list-keys
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

The submitted verification evidence showed two KMS keys and `Verified OK`. Complete KMS Key IDs and ARNs are omitted to meet the redaction requirement.

## 6. Security Best-Practices Checklist

- [x] Data encrypted at rest with AES and decryption verified.
- [x] Asymmetric keys used correctly: encrypt with public key, decrypt/sign with private key, and verify with public key.
- [x] Data protected in transit with TLS — the TLS service ran and the `curl -k` request returned the record successfully.
- [x] Envelope encryption used and plaintext data-key files removed.
- [x] Per-tenant keys used and failed decryption after key disable demonstrated.
- [x] Integrity verified with SHA-256 and a hash chain.

## 7. Missing Steps, Pictures, and Outputs

| Requirement | Status | Finding / action needed |
|---|---|---|
| Task 1 AES encryption/decryption and `MATCH` | Complete | Evidence in `z2.png`–`z4.png`. |
| Task 2 RSA encryption/decryption | Complete | Evidence in `z7.png` and `z8.png`. |
| Task 2 signature verification (`Verified OK`) | Complete | Evidence in `z11.png` and also `66.png`. |
| Task 3 self-signed certificate | Complete | Evidence in `z10.png`. |
| Task 3 TLS container running | Complete | Evidence in `z12.png`. |
| Task 3 `curl -k https://localhost:8443/record.txt` output | Complete | `aaa.png` shows both the command and the returned record. |
| Task 4 tenant A `create-key` response | **Picture/output missing** | Later use proves the key existed, but capture the original create response or a redacted `describe-key` result. |
| Task 4 direct KMS encryption output | Complete, redacted | Original in `z13.png`; ciphertext intentionally not embedded. |
| Task 5 generate data key | Complete, secret-bearing evidence | Original in `z14.png`; plaintext/wrapped values must remain censored. |
| Task 5 local encryption and plaintext-key deletion | Complete | Evidence in `z15.png` and `z16.png`. |
| Task 5 successful envelope decryption | Extra validation complete | Evidence in `34.png`. |
| Task 6 separate tenant B key | Complete, redacted | Original in `2.png`; full IDs intentionally not embedded. |
| Task 6 wrong-tenant-key failure | Complete | Evidence in `3.png`. |
| Task 6 scheduled deletion | Complete, redacted | Original in `33.png`; full Key ID/timestamp not embedded. |
| Task 6 disabled-key failure | Complete, redacted | Original in `22.png`; full ARN intentionally not embedded. |
| Task 7 different SHA-256 hashes | Complete | Evidence in `44.png`. |
| Task 7 hash chain | Complete | Evidence in `55.png`. |
| Cleanup | Complete | `666.png` shows cleanup and no remaining TLS/LocalStack containers. |

### Evidence still recommended

For a clearer redacted tenant A creation record, recreate only if allowed, or run a non-secret metadata check against an existing key and obscure the identifier before submission:

```bash
aws $EP kms describe-key --key-id "$KEY_A" \
  --query 'KeyMetadata.{Description:Description,KeyState:KeyState,KeyUsage:KeyUsage}'
```

This query avoids printing the Key ID and ARN while still documenting the key’s description, state, and use.

## 8. Cleanup

The submitted evidence shows the TLS and LocalStack containers were stopped and the generated lab files were removed. This is appropriate after all evidence has been captured.

```bash
docker stop tls 2>/dev/null
rm -f record.* private.pem public.pem key.pem cert.pem datakey.* tampered.txt
docker stop localstack && docker rm localstack
```

> Cleanup is destructive. It should only be performed after screenshots and required outputs have been saved.

## 9. Conclusion

The lab successfully demonstrated AES encryption at rest, RSA encryption and signatures, TLS encryption in transit, KMS operations, envelope encryption, per-tenant key isolation, key disablement, cryptographic-erasure principles, SHA-256 integrity checks, and a tamper-evident hash chain. The original tenant A key-creation screenshot is absent, although later KMS operations establish that the key existed and was used successfully.
