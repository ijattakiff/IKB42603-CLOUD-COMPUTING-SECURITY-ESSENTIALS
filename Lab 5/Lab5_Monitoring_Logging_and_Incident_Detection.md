# IKB42603 Lab 5: Monitoring, Logging and Incident Detection

## Report Information

- **Course:** IKB42603 Cloud Computing Security Essentials
- **Lab:** Lab 5 - Monitoring, Logging and Incident Detection
- **Environment:** Kali Linux, Docker, AWS CLI, and LocalStack
- **Name:** Muhamad Izzat A'kif Bin Mohd Sanusi
- **ID:** 52215124688

## Credential and Secret Sanitisation

The evidence was checked for passwords, AWS access keys, secret access keys, session tokens, private keys, and other secret values. `12.png` shows LocalStack placeholder values assigned to the AWS access-key and secret-key environment variables. Those values are treated as credentials: they are replaced with `<REDACTED>` in the transcript below, and the original screenshot is deliberately not embedded in this report. The remaining screenshots do not display credential values. The usernames, private/test IP addresses, and LocalStack account ID `000000000000` are lab data rather than credentials. No credential value or secret is reproduced in this report.

## Lab Objectives

This lab demonstrates how to:

1. Generate and centralise application logs.
2. Query security-relevant activity.
3. Make logs tamper-evident with a hash chain.
4. Correlate multiple events to detect an incident.
5. Contain the simulated threat and preserve evidence with an integrity hash.

## Evidence Summary

| Image | Guide step | Evidence shown | Status |
|---|---|---|---|
| `1.png` | Task 1 | Creation and display of the seven-line `auth.log` | Complete |
| `2.png` | Task 2 | Log upload loop and CloudWatch Logs read-back | Complete |
| `3.png` | Task 3 | Four failed logins grouped under `203.0.113.9` | Complete |
| `4.png` | Task 4 | Seven-entry hash-chained log | Complete |
| `5.png` | Task 4 | Original `500MB` value changed to `5MB` | Complete |
| `6.png` | Task 4 | Original and tampered final hashes differ | Complete |
| `7.png` | Task 5 | Counts and correlation alert | Complete |
| `8.png` | Task 6 | Simulated `iptables` containment rule | Complete |
| `9.png` | Task 6 | Timestamped evidence copy and SHA-256 hash file | Complete |
| `10.png` | Verification | Evidence hash verifies as `OK`; log group exists | Complete |
| `11.png` | Setup | LocalStack 4.14.0 container start and healthy status | Complete |
| `12.png` | Setup | LocalStack readiness and creation of `/ccse/app` and `auth` | Reviewed; sanitised transcript used instead of the original image |
| `13.png` | Task 4 | Final hash forwarded to and read back from `/ccse/integrity` | Complete |
| `last.png` | Cleanup | Generated files removed; LocalStack stopped and removed | Complete |

## Session A: Logging and Centralisation

### Setup - Start LocalStack

The LocalStack 4.14.0 image was pulled and started in a container named `localstack`:

```bash
docker run -d \
  --name localstack \
  -p 4566:4566 \
  localstack/localstack:4.14.0
docker ps
```

The `docker ps` result shows the container as healthy with host port `4566` mapped to the service. This directly confirms that LocalStack was running.

![Setup - LocalStack container started and healthy](lab-images/lab5/11.png)

LocalStack then reported `Ready`, and the health endpoint showed the `logs` service as available. The AWS CLI environment and endpoint were configured as follows; the two placeholder credential values have been censored:

```bash
export AWS_ACCESS_KEY_ID=<REDACTED>
export AWS_SECRET_ACCESS_KEY=<REDACTED>
export AWS_DEFAULT_REGION=us-east-1
EP='--endpoint-url=http://localhost:4566'
```

The application log group and stream were created and then verified:

```bash
aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
aws $EP logs describe-log-groups
```

The `describe-log-groups` output contains `/ccse/app`. The original `12.png` also shows the successful, silent `create-log-group` and `create-log-stream` commands, but it is not embedded because it exposes the placeholder credential assignments. The successful log read-back in `2.png` further confirms that the `auth` stream was usable.

**Evidence status:** Complete. LocalStack startup, health, log-group creation, log-stream creation, and verification are supported by the new evidence.

### Task 1 - Generate Application Logs

The authentication log was created with seven events:

```bash
cat > auth.log <<'EOF'
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
EOF

cat auth.log
wc -l auth.log
```

The output confirms that `auth.log` contains seven lines. The sequence includes a normal login, four failed administrator logins, a successful administrator login, and a 500 MB data export.

![Task 1 - Authentication log creation and seven-line count](lab-images/lab5/1.png)

**Result:** Task 1 is complete.

### Task 2 - Centralise Logs in CloudWatch Logs

Each line was sent to the LocalStack CloudWatch Logs endpoint with an increasing timestamp:

```bash
TS=$(date +%s000)
while IFS= read -r line; do
  aws $EP logs put-log-events \
    --log-group-name /ccse/app \
    --log-stream-name auth \
    --log-events timestamp=$TS,message="$line" >/dev/null
  TS=$((TS+1000))
done < auth.log
```

The centralised records were read back using:

```bash
aws $EP logs get-log-events \
  --log-group-name /ccse/app \
  --log-stream-name auth \
  --query 'events[].message' \
  --output text | tr '\t' '\n'
```

The read-back contains all seven original records, including the four failures, later success, and export.

![Task 2 - Centralised CloudWatch Logs read-back](lab-images/lab5/2.png)

**Result:** Task 2 is complete. The application logs were centralised and successfully retrieved.

### Task 3 - Query Security-Relevant Activity

Failed logins were grouped by source IP:

```bash
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

Observed output:

```text
4 ip=203.0.113.9
```

This means that four failed login attempts originated from the same simulated external IP address.

![Task 3 - Failed-login count grouped by IP](lab-images/lab5/3.png)

**Result:** Task 3 is complete. The query identified repeated failures from `203.0.113.9`.

## Session B: Tamper-Proofing, Detection and Response

### Task 4 - Create a Hash-Chained Log

Each log line was combined with the previous SHA-256 hash. The first entry used `0` as the initial previous value:

```bash
PREV=0
while IFS= read -r line; do
  PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
  printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain

cat auth.chain
```

Observed chain hashes:

```text
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5 | 82da89a49dc1ca7d23b8a59f98d7e557ab36ce0c2d0c6e106fabe76e1f0acf39
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9 | 790aef7176d6effe76d077831c071f8500204bf842e7fd8aeda1b67b2e271a97
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9 | 1e0b2e8aaf5143fb95070a8e57b009f058f0d37c257d19409b4131894d29a9a8
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9 | 7fb62c66ded511605e22c8db9c4f57c9360aa27309ce65024a3e5ea35e3b6e94
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9 | 143253b549a74b9626e910fbe54ca12cb5431a0a4c9c4f2189ff27a3e2a17e01
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9 | 4cbfab7fecb703cf21f5df81b47dbf3a727c94442b09b714ac4bfaa3584cc638
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB | ababa787b4bf524d9daddca8c48e4909fc105769a6f17574f42cefe8f81233cf
```

![Task 4 - Hash-chained authentication log](lab-images/lab5/4.png)

The export size was then changed from `500MB` to `5MB` in a tampered copy:

```bash
sed 's/500MB/5MB/' auth.log > auth.tampered
tail -n 1 auth.log
tail -n 1 auth.tampered
```

Observed final lines:

```text
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=5MB
```

![Task 4 - Original and tampered export values](lab-images/lab5/5.png)

The chain was recomputed for the tampered file and the final hashes were compared:

```bash
PREV=0
while IFS= read -r line; do
  PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
  printf '%s | %s\n' "$line" "$PREV"
done < auth.tampered > auth.tampered.chain

ORIGINAL_FINAL=$(tail -n 1 auth.chain | cut -d'|' -f2 | xargs)
TAMPERED_FINAL=$(tail -n 1 auth.tampered.chain | cut -d'|' -f2 | xargs)

echo "Original final hash: $ORIGINAL_FINAL"
echo "Tampered final hash: $TAMPERED_FINAL"

if [ "$ORIGINAL_FINAL" != "$TAMPERED_FINAL" ]; then
  echo "TAMPERING DETECTED: final hashes do not match"
else
  echo "No tampering detected"
fi
```

Observed output:

```text
Original final hash: ababa787b4bf524d9daddca8c48e4909fc105769a6f17574f42cefe8f81233cf
Tampered final hash: 72f1d53774a3a938fa7bd3a88f67894e5a64055a41ee7511eac53d7bd89d859b
TAMPERING DETECTED: final hashes do not match
```

![Task 4 - Final-hash comparison detects tampering](lab-images/lab5/6.png)

**Result:** Task 4 is complete. Changing the export size produced a different final hash, proving that the modification was detected.

#### Forward the Trusted Final Hash

The final hash was forwarded to a separate CloudWatch Logs group and stream so that the integrity record was not kept only beside the application log:

```bash
aws $EP logs create-log-group \
  --log-group-name /ccse/integrity

aws $EP logs create-log-stream \
  --log-group-name /ccse/integrity \
  --log-stream-name final-hashes

FINAL_HASH=$(tail -n 1 auth.chain | cut -d'|' -f2 | xargs)
HASH_TS=$(date +%s000)

aws $EP logs put-log-events \
  --log-group-name /ccse/integrity \
  --log-stream-name final-hashes \
  --log-events "timestamp=$HASH_TS,message=source=auth.log final_hash=$FINAL_HASH"

aws $EP logs get-log-events \
  --log-group-name /ccse/integrity \
  --log-stream-name final-hashes \
  --query 'events[].message' \
  --output text
```

Observed read-back:

```text
source=auth.log final_hash=ababa787b4bf524d9daddca8c48e4909fc105769a6f17574f42cefe8f81233cf
```

The evidence shows one repeated `create-log-group` attempt returning `ResourceAlreadyExistsException`; this is expected because `/ccse/integrity` had already been created successfully. The later upload and read-back confirm that the operation continued successfully.

![Task 4 - Final hash forwarded to the separate integrity log group](lab-images/lab5/13.png)

**Result:** Forwarding to a separate central log group is evidenced. An access policy or configuration proving strict append-only enforcement is not shown.

### Task 5 - Detect the Incident by Correlation

The failures, success, and export were counted for the same IP address:

```bash
IP=203.0.113.9
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)

echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"

if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
  echo 'ALERT: probable brute-force -> compromise -> data exfiltration'
fi
```

Observed output:

```text
IP=203.0.113.9 fails=4 success=1 export=1
ALERT: probable brute-force -> compromise -> data exfiltration
```

![Task 5 - Correlation counts and incident alert](lab-images/lab5/7.png)

**Result:** Task 5 is complete. Correlation identified the sequence of brute-force attempts, likely account compromise, and possible data exfiltration.

### Task 6 - Incident Response

#### Containment

The source IP was blocked with a simulated `iptables` rule inside an isolated Alpine container:

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
  'apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2'
```

Observed output:

```text
target  prot opt source          destination
DROP    all  --  203.0.113.9    0.0.0.0/0
```

![Task 6 - Simulated containment rule](lab-images/lab5/8.png)

This demonstrates the intended containment action. Because the rule was created in a container launched with `--rm`, it is a temporary lab model rather than a persistent host or production firewall rule.

#### Evidence Collection and Integrity

The original log was copied into a date-stamped evidence file and hashed:

```bash
cp auth.log evidence_$(date +%Y%m%d).log
ls -l evidence_*.log
sha256sum evidence_*.log > evidence.sha256
cat evidence.sha256
```

Observed output:

```text
-rw-rw-r-- 1 alipmaz alipmaz 404 Aug 26 17:35 evidence_20260826.log
0adc5d2ac06cbbdd366099bcc0540c4c0f76946e71b52e4c99322731696a203b  evidence_20260826.log
```

![Task 6 - Timestamped evidence file and SHA-256 hash](lab-images/lab5/9.png)

**Result:** Task 6 is complete. The suspicious IP was contained in the lab model, and a timestamped copy of the log was preserved with a recorded SHA-256 digest.

## Incident Report

### Detection

Monitoring identified four failed login attempts against the `admin` account from `203.0.113.9`. The same IP then produced one successful administrator login followed by a 500 MB `EXPORT_DATA` action. A correlation rule combined these records and generated the alert `probable brute-force -> compromise -> data exfiltration`.

### Analysis

The sequence is consistent with a brute-force or password-guessing attack that succeeded on the fifth authentication attempt. The successful login alone could have been legitimate, and the export alone could have been an authorised activity. Their shared source IP and close timing after four failures make the combined sequence suspicious and indicate likely account compromise followed by possible data exfiltration.

#### Incident timeline

| Time | Observed activity | Interpretation |
|---|---|---|
| `2025-03-01 09:00:01` | `ahmad` logged in from `10.0.0.5` | Baseline successful login from a different source |
| `2025-03-01 09:01:10` to `09:01:18` | Four failed `admin` logins from `203.0.113.9` | Probable brute-force or password-guessing attempts |
| `2025-03-01 09:01:22` | Successful `admin` login from `203.0.113.9` | Possible account compromise |
| `2025-03-01 09:01:40` | 500 MB export by `admin` from `203.0.113.9` | Possible data exfiltration |
| Time not recorded in screenshot | Correlation alert generated | Incident detected |
| Time not recorded in screenshot | DROP rule added for `203.0.113.9` | Simulated containment |
| `2026-08-26 17:35` filesystem time | `evidence_20260826.log` shown in evidence | Evidence copy documented and hashed |

The authentication records provide an exact simulated attack timeline. The screenshots do not display execution times for the alert or containment commands, so the response-action portion of the timeline cannot be timed precisely from the supplied evidence.

### Containment

The suspected source `203.0.113.9` was blocked with an `iptables` DROP rule in the lab container. This action models immediate containment by preventing further traffic from the source. In a production environment, the equivalent rule would need to be placed at a persistent enforcement point, such as the host firewall, cloud security control, web application firewall, or network perimeter.

### Evidence & integrity

The original `auth.log` was retained, centralised in the `/ccse/app` CloudWatch Logs group, copied to `evidence_20260826.log`, and hashed. The recorded evidence SHA-256 digest is `0adc5d2ac06cbbdd366099bcc0540c4c0f76946e71b52e4c99322731696a203b`. Running `sha256sum -c evidence.sha256` returned `OK`, confirming that the evidence copy still matched the recorded digest. The hash chain separately showed that changing the export size altered the final chain hash and therefore exposed tampering. Its trusted final hash was also forwarded to the separate `/ccse/integrity` log group and successfully read back.

### Lesson learned

Individual log records may appear harmless when reviewed separately. Centralised logging, time-ordered correlation, and integrity protection are all necessary to detect an attack sequence and preserve trustworthy evidence. Forwarding the final hash to `/ccse/integrity` separates it from the application log; production use should additionally enforce append-only permissions so that an attacker who compromises the application cannot rewrite both the log and its integrity record.

## Short-Answer Questions

### 1. What is the difference between a log and an event? Give an example of each from this lab.

A **log** is a durable record describing an activity that occurred. An example is:

```text
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
```

An **event** is a meaningful occurrence or trigger derived from one or more observations, often processed in near real time. An example is the alert raised after the system detected at least three failures, a later success, and an export from the same IP:

```text
ALERT: probable brute-force -> compromise -> data exfiltration
```

### 2. Why must audit logs be tamper-proof, and how does a hash chain achieve this?

Audit logs support investigation, accountability, and compliance. If an attacker can change or delete records without detection, investigators cannot trust the timeline or prove what occurred. A hash chain calculates each entry's hash from both the current log line and the previous entry's hash. Altering an entry changes its hash and breaks that entry and every later dependent hash. Comparing a trusted final hash with a recomputed value therefore exposes modification. Strictly, this makes the log **tamper-evident**; protection also requires storing the trusted hash or chain in a separate append-only location.

### 3. How did correlation detect an incident that no single log line revealed?

The script grouped records by `203.0.113.9` and combined three conditions: four login failures, one later successful login, and one data export. A failed login can be an ordinary user mistake, a successful login can be legitimate, and an export can be authorised. When the same IP performs all three actions in sequence, the combined pattern indicates probable brute-force access followed by compromise and data exfiltration.

### 4. List the incident-response steps you performed and the goal of each.

1. **Detect:** Counted and correlated authentication and export activity to identify the suspicious sequence.
2. **Analyse:** Reviewed the common IP, event types, order, and counts to assess the likely attack.
3. **Contain:** Added a DROP rule for `203.0.113.9` to model stopping further malicious traffic.
4. **Collect evidence:** Copied the original log into a date-stamped evidence file so the incident record could be preserved.
5. **Preserve integrity:** Created and verified a SHA-256 digest so later changes to the evidence could be detected.
6. **Document and build a timeline:** Recorded the ordered authentication and export events, response actions, evidence, integrity results, and lesson learned. The alert and containment times remain unspecified because their screenshots contain no execution timestamps.

### 5. How do the same logs serve both security monitoring and compliance evidence (Weeks 6 and 11)?

For security monitoring, the logs provide timely visibility into failed logins, successful access, source IP addresses, and data-export activity. These records can feed queries and correlation rules that detect threats. For compliance, the same logs provide a retained audit trail showing who performed an action, what happened, when it occurred, and where it originated. Centralisation, access control, retention, timestamps, and integrity verification make the records suitable for audits and investigations. Compliance value depends on preserving the logs under an approved retention policy and protecting them from unauthorised alteration.

## Verification

The evidence digest was verified with:

```bash
sha256sum -c evidence.sha256
```

Observed output:

```text
evidence_20260826.log: OK
```

The LocalStack CloudWatch Logs configuration was checked with:

```bash
aws $EP logs describe-log-groups
```

The output contains:

```text
logGroupName: /ccse/app
logGroupClass: STANDARD
arn: arn:aws:logs:us-east-1:000000000000:log-group:/ccse/app:*
```

The all-zero account number belongs to the LocalStack lab environment and is not a real AWS account credential.

![Verification - Evidence integrity and LocalStack log group](lab-images/lab5/10.png)

## Security Best-Practices Checklist

- [x] Logs were centralised instead of being left only on the application host.
- [x] Failed-login activity was queried and grouped by IP.
- [x] Logs are tamper-evident through a hash chain, and the final hash was forwarded to the separate `/ccse/integrity` log group.
- [x] Multiple records were correlated into one incident alert.
- [x] Incident response covered detection, analysis, simulated containment, evidence collection, integrity verification, and documentation.

## Cleanup and Teardown

After completing and verifying the lab, the generated log and evidence files were removed. The LocalStack container was then stopped and removed:

```bash
cd ~/IKB42603-Lab5

rm -f auth.log auth.chain auth.tampered \
  auth.tampered.chain evidence_*.log evidence.sha256

docker stop localstack
docker rm localstack
```

Observed container-command output:

```text
localstack
localstack
```

The two `localstack` lines confirm successful completion of `docker stop` and `docker rm`. The `rm -f` command normally produces no output when successful.

![Cleanup - Generated files and LocalStack container removed](lab-images/lab5/last.png)

## Conclusion

The lab successfully demonstrated LocalStack setup, centralised logging, security queries, tamper detection, forwarding of the trusted final hash, event correlation, simulated containment, evidence-integrity verification, and environment teardown. The activity from `203.0.113.9` was correctly identified as probable brute force followed by account compromise and data exfiltration. All core assessed deliverables and cleanup steps are supported by the submitted evidence.
