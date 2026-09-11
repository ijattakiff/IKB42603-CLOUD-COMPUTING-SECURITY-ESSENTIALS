## Course Information
---
*Course:* IKB42603 Cloud Computing Security Essentials

*Lab:* Lab 6

*Name:* MUHAMMAD AMEER BIN IDRIS

*Date:* 9 SEPTEMBER 2026

*ID:* 52215124748

# IKB42603 Lab 6: Object Storage & Data Lifecycle

## Session A (Week 11) — Object Storage & the Exposure Problem

### One-Time Environment Setup
Start a clean, activated LocalStack instance and set up the environment with `ENFORCE_IAM=1` to ensure IAM policies are properly evaluated.

<img src="Evidence/1. start clean.png" alt="start clean" />

Point the AWS CLI at the LocalStack endpoint so all commands interact with our local environment.

<img src="Evidence/2. Point the CLI at LocalStack.png" alt="Point the CLI at LocalStack" />

### Task 1 — Classify the Data Before You Store It
Security decisions should always follow data classification. We begin by creating an S3 bucket for a hospital records system and preparing three text objects of varying sensitivity (`public`, `internal`, and `confidential`).

Upload the objects to the bucket and tag each with its proper classification to establish a foundation for applying granular security controls later.

<img src="Evidence/3. Classify the Data Before You Store It.png" alt="Classify the Data Before You Store It" />
<img src="Evidence/4. Classify the Data Before You Store It.png" alt="Classify the Data Before You Store It" />

List the objects in the bucket to verify they have been successfully stored.

<img src="Evidence/5. Classify the Data Before You Store It.png" alt="Classify the Data Before You Store It" />

Retrieve the object tags to confirm the `confidential` classification tag is properly applied.

<img src="Evidence/6. Classify the Data Before You Store It.png" alt="Classify the Data Before You Store It" />

### Task 2 — Reproduce the Archetypal Breach
The most common cause of cloud data leaks is an overly permissive bucket policy. We deliberately reproduce this vulnerability by applying a bucket policy with `"Principal": "*"`, which exposes the bucket to the entire internet.

<img src="Evidence/7. Reproduce the Archetypal Breach.png" alt="Reproduce the Archetypal Breach" />

We confirm the breach by anonymously fetching the `confidential` record via a simple `curl` request, proving the data is exposed without any AWS credentials.

<img src="Evidence/8. no AWS credentials-no CLI,-just a URL.png" alt="no AWS credentials-no CLI,-just a URL" />

### Task 3 — Remediate with Block Public Access
To fix the exposure, we first delete the offending public policy.

<img src="Evidence/9. Remove the offending policy.png" alt="Remove the offending policy" />

To prevent this from happening again in the future, we apply an account-level guardrail called **Block Public Access**. This feature blocks any future attempts to apply public policies or ACLs.

<img src="Evidence/10. Apply the account-level guardrail to the bucket.png" alt="Apply the account-level guardrail to the bucket" />

We test the guardrail by attempting to re-introduce the public policy. The guardrail actively refuses the operation.

<img src="Evidence/11. Try to re-introduce the public policy - the guardrail should refuse it.png" alt="Try to re-introduce the public policy" />

We re-test the anonymous read request via `curl` to ensure the bucket is no longer publicly accessible.

<img src="Evidence/12. Re-test the anonymous read.png" alt="Re-test the anonymous read" />

Finally, we replace the policy with a least-privilege approach, restricting read access strictly to our own account and scoped only to the `internal/` prefix.

<img src="Evidence/13. read access for your own account only.png" alt="read access for your own account only" />

### Task 4 — Identity Policy vs Resource Policy
We create an IAM user ("DataAnalyst") whose policy allows reading everything across S3.

<img src="Evidence/14. An analyst whose IAM policy allows reading everything.png" alt="An analyst whose IAM policy allows reading everything" />

We note both the Access Key and Secret Key for the new user so we can test access.

<img src="Evidence/15. Note both values - you will paste them into a named profile.png" alt="Note both values" />

We copy the two values into our variables to configure a named AWS CLI profile for the analyst.

<img src="Evidence/16. Copy the two values into these variables - keep the quotes.png" alt="Copy the two values into these variables" />

We add a bucket policy that explicitly denies the analyst access to the `confidential/` prefix, creating a disagreement between the Identity Policy (Allow) and Resource Policy (Deny).

<img src="Evidence/17.Now the bucket owner disagrees about one prefix.png" alt="Now the bucket owner disagrees about one prefix" />

The analyst attempts to read the `internal/` record. This succeeds because it is allowed by the Identity Policy and not denied by the Resource Policy.

<img src="Evidence/18. Should SUCCEED - allowed by both policies.png" alt="Should SUCCEED" />

The analyst attempts to read the `confidential/` record. This fails because an explicit `Deny` in the Resource Policy always overrides the `Allow` in the Identity Policy.

<img src="Evidence/19. Should FAIL - IAM allows, but the bucket policy explicitly denies.png" alt="Should FAIL" />

## Session B (Week 12) — Protecting, Retaining and Retiring Data

### Task 5 — Default Encryption at Rest (SSE-KMS)
We create a dedicated customer-managed KMS key for the bucket and configure default Server-Side Encryption (SSE-KMS) for the bucket using this key.

<img src="Evidence/20. A dedicated key for this bucket.png" alt="A dedicated key for this bucket" />

We upload a new record with NO explicit encryption flags. The bucket automatically encrypts it using the default KMS key, guaranteeing data protection at rest.

<img src="Evidence/21. Upload with NO encryption flags at all.png" alt="Upload with NO encryption flags at all" />

### Task 6 — Delegated Access and the Condition-Key Trap
We generate a **Presigned URL** to grant time-bounded, signed, single-object access to someone without AWS credentials.

<img src="Evidence/22. Time-bounded-signed- single-object access.png" alt="Time-bounded-signed- single-object access" />

We paste the URL into a variable and successfully fetch the record using `curl`.

<img src="Evidence/23.Paste the URL into the variable - keep the quotes.png" alt="Paste the URL into the variable" />

We wait for the pre-signed URL to lapse (expire), then try the exact same URL again. It correctly denies access.

<img src="Evidence/24. Wait for it to lapse- then try the same url again.png" alt="Wait for it to lapse" />

We apply a bucket policy condition (`aws:SecureTransport`) that enforces TLS (HTTPS). Any ordinary call over HTTP (which LocalStack uses locally) is now refused, trapping our requests.

<img src="Evidence/25. Any ordinary call - expect it to be refused.png" alt="Any ordinary call - expect it to be refused" />

We recover by deleting the bucket policy before continuing with the rest of the lab.

<img src="Evidence/26. Recover before continuing.png" alt="Recover before continuing" />

### Task 7 — Versioning, Delete Markers & Data Remanence
We enable bucket versioning. To an ordinary reader, deleting an object just hides it, but earlier tasks showed remanence inside a container volume. Object storage has its own version of this.

<img src="Evidence/27. showed remanence inside a container volume.png" alt="showed remanence inside a container volume" />

We upload two more revisions of the same confidential record.

<img src="Evidence/28. Two more revisions of the same record.png" alt="Two more revisions of the same record" />

We "delete" the record using the standard delete command.

<img src="Evidence/29. 'delete' the record .png" alt="'delete' the record" />

Because versioning is enabled, a delete marker is placed on top and is now the current version.

<img src="Evidence/30. A delete marker is now the current version.png" alt="A delete marker is now the current version" />

To an ordinary reader, the object appears to be completely gone.

<img src="Evidence/31. To an ordinary reader the object is gone.png" alt="To an ordinary reader the object is gone" />

However, if we query the specific older version ID, the original, unredacted record is still there (data remanence).

<img src="Evidence/32. unredacted record is still there.png" alt="unredacted record is still there" />

To comply with privacy laws, we must perform a permanent, per-version deletion by specifying the version ID explicitly.

<img src="Evidence/33. Permanent-per-version deletion.png" alt="Permanent-per-version deletion" />

### Task 8 — Lifecycle, Retention & Cryptographic Erasure
We apply a Lifecycle Configuration, which serves as the automated, auditable expression of our retention policy, expiring old versions automatically.

<img src="Evidence/34. A lifecycle configuration is the automated_auditable expression of your retention policy.png" alt="A lifecycle configuration" />

We demonstrate the fastest deletion method available in the cloud: **Cryptographic Erasure**. We disable and schedule the KMS key for deletion. Destroy the key and the ciphertext instantly becomes unrecoverable noise.

<img src="Evidence/35. Destroy the key and the ciphertext becomes unrecoverable noise.png" alt="Destroy the key" />

We attempt to read an object encrypted under the disabled key to prove the data is now completely inaccessible.
<img src="Evidence/36. Attempt to read an object encrypted under the disabled key.png" alt="Attempt to read an object encrypted under the disabled key" />

### Verification
We run the final verification commands to output the bucket's final security posture as requested by the auditor.

<img src="Evidence/37. prove the bucket's final security posture.png" alt="prove the bucket's final security posture" />

### Cleanup & Teardown
To fully delete a versioned bucket, we cannot use a simple force delete. We must first list and remove every object version and delete marker explicitly before the bucket becomes empty and can be destroyed.

<img src="Evidence/38. Cleanup & Teardown.png" alt="Cleanup & Teardown" />
<img src="Evidence/39. remove every version explicitly.png" alt="remove every version explicitly" />

---

## Deliverables & Assessment

### 2. Data Classification Table
| Classification | Who may read it | Impact if leaked | Control you will apply |
|---|---|---|---|
| public | Anyone / Public | Low / None | Block Public Access (Guardrail) |
| internal | Internal Staff | Medium | Resource-based Policy (Least Privilege) |
| confidential | Specific Authorized Personnel | High / Critical | Default Encryption (SSE-KMS), Versioning & Lifecycle Management |

### 3. Short-Answer Questions

**Q: Which single element of the Task 2 policy caused the exposure, and why is Principal: "*" more dangerous on a bucket policy than an over-broad IAM policy attached to one user?**
**A:** The single element that caused the exposure was `"Principal": "*"`. It is highly dangerous on a bucket policy because it grants access to anyone on the internet, including completely anonymous users without AWS credentials. An over-broad IAM policy only grants access to the specific authenticated user it is attached to.

**Q: Explain the difference between an identity-based policy and a resource-based policy. In Task 4, which one decided each of the analyst's two requests?**
**A:** An identity-based policy is attached to an IAM identity (user/role) and defines what they can do. A resource-based policy is attached to a resource (like an S3 bucket) and defines who can access it. In Task 4, the read request for `internal` was evaluated and allowed primarily by the identity-based policy. The read request for `confidential` was explicitly denied by the resource-based policy, overriding the identity-based allow.

**Q: Block Public Access is described as a guardrail rather than a control. What is the difference, and why does the distinction matter for an organisation with many engineers?**
**A:** A control (like an IAM policy) explicitly grants or denies access. A guardrail operates globally at a higher level, enforcing strict boundaries that override unsafe configurations. For an organization with many engineers, a guardrail ensures that even if a developer makes a mistake and tries to apply a public bucket policy, it will be automatically blocked, acting as a fail-safe mechanism against misconfigurations.

**Q: Your bucket has default SSE-KMS encryption. Does that protect the confidential record from the analyst in Task 4? Explain precisely what server-side encryption does and does not defend against.**
**A:** No, SSE-KMS does not protect the record if the analyst has IAM permissions to read the S3 object and use the KMS key. Server-side encryption defends against unauthorized access to the underlying physical storage media (e.g., if hard drives are compromised) and allows for cryptographic erasure. It does not defend against unauthorized access at the application/API layer if a user is granted the required logical permissions.

**Q: A patient invokes their right to erasure. Using your Task 7 evidence, explain why delete-object alone is not compliant, and describe two mechanisms that would make the deletion provable.**
**A:** With versioning enabled, `delete-object` alone merely creates a delete marker while retaining the original data underneath (data remanence), which means the data is not actually erased. Two mechanisms for provable deletion are:
1. **Permanent per-version deletion**: Explicitly specifying the `version-id` in the delete request.
2. **Cryptographic erasure**: Deleting the KMS encryption key that protects the data, rendering all versions unrecoverable.

**Q: You are the auditor in Week 11. Name three commands from this lab whose output you would collect as compliance evidence, and state which control each one evidences.**
**A:**
1. `aws s3api get-public-access-block` - Evidences the guardrail control preventing public exposure.
2. `aws s3api get-bucket-encryption` - Evidences the control for default encryption at rest.
3. `aws s3api get-bucket-lifecycle-configuration` - Evidences the control for automated data retention/retirement policies.
