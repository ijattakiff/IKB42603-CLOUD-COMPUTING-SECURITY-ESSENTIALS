# IKB42603 Cloud Computing Security Essentials

## Lab 4: Access Control and Network Security

**Student name:** Muhamad Izzat A'kif Bin Mohd Sanusi<br>
**Student ID:** 52215124688<br>
**Lab:** Lab 4 — Access Control and Network Security (Week 4)<br>
**Report date:** 3 September 2026

> **Privacy note:** Passwords, the TOTP shared secret, and all one-time codes have been replaced with redaction markers in commands, outputs, and report images. The report uses only the redacted evidence copies in `lab-images/lab4/`.

## Lab objectives

This lab demonstrates how to:

1. Distinguish authentication (AuthN) from authorization (AuthZ).
2. validate a time-based one-time password as a second authentication factor.
3. enforce least-privilege access with Kubernetes role-based access control (RBAC).
4. segment a three-tier application so the frontend cannot contact the database directly.
5. apply a default-deny firewall policy.
6. reduce a container's attack surface and scan an image for known vulnerabilities.

## Task 1 — Password-protected service

### Objective

Run an Nginx service protected by HTTP Basic authentication and confirm that an unauthenticated request is rejected while a request with valid credentials is accepted.

### Procedure

1. A bcrypt password entry was generated for the `student` user. The password is not reproduced in this report.

   ```bash
   docker run --rm httpd:alpine \
     htpasswd -nbB student '<REDACTED_PASSWORD>' > htpasswd.txt
   ```

2. A static response page was created.

   ```bash
   printf 'Authenticated OK\n' > index.html
   ```

3. `default.conf` was configured to protect the page using the mounted password file.

   ```nginx
   server {
       listen 80;
       server_name _;

       location / {
           auth_basic "Restricted";
           auth_basic_user_file /etc/nginx/.htpasswd;
           root /usr/share/nginx/html;
           index index.html;
       }
   }
   ```

4. The service was started on host port `8080`. Configuration, credential, and content files were mounted read-only.

   ```bash
   docker run --rm -d \
     --name authsvc \
     -p 8080:80 \
     -v "$(pwd)/default.conf:/etc/nginx/conf.d/default.conf:ro" \
     -v "$(pwd)/htpasswd.txt:/etc/nginx/.htpasswd:ro" \
     -v "$(pwd)/index.html:/usr/share/nginx/html/index.html:ro" \
     nginx:alpine
   ```

5. The endpoint was tested without credentials and then with valid credentials.

   ```bash
   curl -s -o /dev/null \
     -w 'no-creds: %{http_code}\n' \
     http://localhost:8080

   curl -s -o /dev/null \
     -w 'valid-creds: %{http_code}\n' \
     -u student:'<REDACTED_PASSWORD>' \
     http://localhost:8080

   curl -s -u student:'<REDACTED_PASSWORD>' http://localhost:8080
   ```

### Result

```text
no-creds: 401
valid-creds: 200
Authenticated OK
```

The `401 Unauthorized` result shows that the service rejected a request with no credentials. The `200 OK` result and response body show that authentication succeeded when valid credentials were supplied.

![Task 1 password setup with credential redacted](lab-images/lab4/task1_password_setup_redacted.png)

![Task 1 authentication results with credential redacted](lab-images/lab4/task1_authentication_results_redacted.png)

## Task 2 — Multi-factor authentication with TOTP

### Objective

Generate and validate a six-digit time-based one-time password (TOTP) as a second authentication factor.

### Procedure

1. A random Base32 shared secret was generated. Its value is redacted.

   ```bash
   SECRET=$(head -c 20 /dev/urandom | base32 | tr -d '\n')
   echo "Enrol this secret in an authenticator app: <REDACTED_TOTP_SECRET>"
   oathtool --totp -b "$SECRET"
   ```

2. A user-supplied code was compared with the current expected code.

   ```bash
   printf 'Enter the 6-digit code: '
   read CODE
   EXPECTED=$(oathtool --totp -b "$SECRET")

   if [ "$CODE" = "$EXPECTED" ]; then
       echo 'MFA OK'
   else
       echo 'MFA FAILED'
   fi
   ```

3. The first comparison failed because the TOTP had changed or did not match. A fresh code was then generated and immediately validated.

### Result

```text
TOTP shared secret: [REDACTED]
TOTP codes: [REDACTED]
First validation: MFA FAILED
Fresh-code validation: MFA OK
```

The required successful `MFA OK` result is present. The earlier failed attempt does not invalidate the task; it demonstrates that a wrong or expired TOTP is rejected.

![Task 2 MFA evidence with shared secret and one-time codes redacted](lab-images/lab4/task2_mfa_redacted.png)

## Task 3 — Kubernetes authorization with RBAC

### Objective

Create a service account whose permissions are limited to reading pods, then verify that write and delete actions are denied.

### Procedure

1. A kind cluster named `ccse-lab4` was created and allowed to reach the `Ready` state.

   ```bash
   kind create cluster --name ccse-lab4
   kubectl cluster-info
   kubectl get nodes
   ```

2. The application namespace and developer service account were created.

   ```bash
   kubectl create namespace app
   kubectl create serviceaccount dev -n app
   ```

3. A namespaced role permitting only `get` and `list` on pods was created and bound to the service account.

   ```bash
   kubectl create role dev-role \
     -n app \
     --verb=get,list \
     --resource=pods

   kubectl create rolebinding dev-rb \
     -n app \
     --role=dev-role \
     --serviceaccount=app:dev
   ```

4. Kubernetes authorization checks were performed while impersonating the service account.

   ```bash
   SA=system:serviceaccount:app:dev
   kubectl auth can-i list pods -n app --as="$SA"
   kubectl auth can-i create deployments -n app --as="$SA"
   kubectl auth can-i delete pods -n app --as="$SA"
   ```

### Result

| Authorization test | Result | Interpretation |
|---|---:|---|
| List pods | `yes` | Allowed by `dev-role` |
| Create deployments | `no` | Not granted |
| Delete pods | `no` | Not granted |

The results demonstrate least privilege: the developer identity can inspect pods but cannot create deployments or delete pods.

![Task 3 cluster and service-account setup](lab-images/lab4/task3_cluster_setup.png)

![Task 3 RBAC results and role-binding verification](lab-images/lab4/task3_rbac_results_and_verification.png)

## Task 4 — Three-tier network segmentation

### Objective

Place the database, application, and web tiers on separate Docker networks so that only the application tier can reach the database.

### Procedure

1. Two isolated bridge networks were created.

   ```bash
   docker network create frontend-net
   docker network create backend-net
   ```

2. The database was attached only to `backend-net`, the application was attached to both networks, and the web tier was attached only to `frontend-net`.

   ```bash
   docker run -d --name db --network backend-net redis:alpine
   docker run -d --name app --network backend-net nginx:alpine
   docker network connect frontend-net app
   docker run -d --name web --network frontend-net nginx:alpine
   ```

3. Netcat was installed in the test containers, and connectivity to Redis port `6379` was checked.

   ```bash
   docker exec web sh -c 'apk add --no-cache -q netcat-openbsd >/dev/null'
   docker exec app sh -c 'apk add --no-cache -q netcat-openbsd >/dev/null'

   docker exec web sh -c '
     if nc -z -w3 db 6379 2>/dev/null; then
       echo "web -> db: UNEXPECTEDLY REACHABLE"
     else
       echo "web -> db: BLOCKED"
     fi'

   docker exec app sh -c '
     if nc -z -w3 db 6379 2>/dev/null; then
       echo "app -> db: REACHABLE"
     else
       echo "app -> db: FAILED"
     fi'
   ```

### Result

```text
web -> db: BLOCKED
app -> db: REACHABLE
```

The frontend cannot resolve or connect directly to the database because it does not share `backend-net`. The application can connect because it is the only tier attached to both networks.

The evidence also shows a duplicate-name warning when `web` was started a second time. The subsequent `docker ps` output confirms that the intended `web`, `app`, and `db` containers were already running, and both connectivity results are valid.

![Task 4 network and container setup](lab-images/lab4/task4_network_setup.png)

![Task 4 blocked and reachable connectivity results](lab-images/lab4/task4_segmentation_results.png)

## Task 5 — Default-deny firewall

### Objective

Model a host firewall that denies incoming traffic by default and permits only HTTPS and loopback traffic.

### Procedure

The rules were applied inside a disposable Alpine container with the `NET_ADMIN` capability.

```bash
docker run --rm \
  --cap-add=NET_ADMIN \
  alpine sh -c '
    apk add --no-cache -q iptables
    iptables -P INPUT DROP
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -L INPUT -n --line-numbers
  '
```

### Result

```text
Chain INPUT (policy DROP)
num  target  prot  source     destination  options
1    ACCEPT  tcp   0.0.0.0/0  0.0.0.0/0    tcp dpt:443
2    ACCEPT  all   0.0.0.0/0  0.0.0.0/0
```

All inbound traffic is denied unless it matches an explicit allow rule. Port `443/tcp` is permitted, and loopback traffic is retained for local inter-process communication.

![Task 5 default-deny iptables rules](lab-images/lab4/task5_default_deny_firewall.png)

## Task 6 — Container hardening and vulnerability scanning

### Objective

Reduce the privileges and writable surface of a web container, verify the controls, and scan an image for high- and critical-severity vulnerabilities.

### Procedure

1. An unprivileged Nginx container was started with a numeric non-root identity, a read-only root filesystem, no Linux capabilities, no-new-privileges, and a temporary in-memory `/tmp` filesystem.

   ```bash
   docker run -d \
     --name hardened \
     --user 1000:1000 \
     --read-only \
     --cap-drop=ALL \
     --security-opt no-new-privileges \
     --tmpfs /tmp \
     nginxinc/nginx-unprivileged
   ```

2. The container status and logs were checked. Nginx started successfully; the expected read-only warning confirmed that modification of the default configuration was blocked.

3. The hardening configuration was verified.

   ```bash
   docker inspect hardened \
     --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'

   docker inspect hardened \
     --format 'CapDrop={{json .HostConfig.CapDrop}}'

   docker inspect hardened \
     --format 'SecurityOptions={{json .HostConfig.SecurityOpt}}'
   ```

### Verification result

```text
User=1000:1000 ReadOnly=true
CapDrop=["ALL"]
SecurityOptions=["no-new-privileges"]
```

![Task 6 hardened container startup and logs](lab-images/lab4/task6_hardened_container.png)

![Task 6 inspect verification](lab-images/lab4/task6_inspect_verification.png)

4. Trivy was run against the Alpine Nginx image, restricted to high- and critical-severity vulnerabilities.

   ```bash
   docker run --rm aquasec/trivy:latest \
     image \
     --scanners vuln \
     --severity HIGH,CRITICAL \
     nginx:alpine | tee trivy-scan.txt
   ```

### Scan result

```text
Target: nginx:alpine (alpine 3.24.1)
Type: alpine
HIGH/CRITICAL vulnerabilities: 0
```

The result means that Trivy found no high- or critical-severity operating-system package vulnerabilities in the scanned image and database at that time. It does not guarantee that the image has no vulnerabilities of lower severity or vulnerabilities unknown to the scanner.

![Task 6 Trivy database download and scan](lab-images/lab4/task6_trivy_download_and_scan.png)

![Task 6 Trivy report summary](lab-images/lab4/task6_trivy_summary.png)

### Hardening measures and reduced attack surfaces

| Hardening measure | Evidence | Attack or exposure reduced |
|---|---|---|
| Run as `1000:1000` | `User=1000:1000` | Limits the impact of remote code execution by preventing the service from starting with root privileges. |
| Read-only root filesystem | `ReadOnly=true` | Blocks modification of application and system files, reducing malware persistence and tampering. |
| Drop all Linux capabilities | `CapDrop=["ALL"]` | Removes privileged kernel operations that could be abused for container escape, network manipulation, or host changes. |
| `no-new-privileges` | Inspect output | Prevents processes from acquiring additional privileges through set-user-ID binaries or file capabilities. |
| `tmpfs /tmp` | Run command | Provides required temporary storage without making the root filesystem writable; contents are non-persistent. |
| Alpine scan target | Trivy summary | Uses and checks a smaller package base, reducing the number of components that may contain known vulnerabilities. |

## Required verification commands

### Kubernetes role binding

```bash
kubectl get rolebinding dev-rb -n app -o yaml
```

The captured YAML identifies `dev-rb`, references `dev-role`, and binds the `dev` service account in the `app` namespace. This output is visible in the Task 3 RBAC evidence.

### Dropped container capabilities

```bash
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'
```

```text
["ALL"]
```

This output is visible in the Task 6 inspect evidence.

## Short-answer questions

### Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.

Authentication verifies **who an identity is**. In Task 1, Nginx challenged the client for a username and password: no credentials produced HTTP `401`, while valid credentials produced HTTP `200`. Authorization decides **what an authenticated identity may do**. In Task 3, the `dev` service account was recognized as an identity, but its RBAC role allowed only pod-reading operations. It could list pods but could not create deployments or delete pods. Therefore, authentication precedes authorization, but successful authentication does not automatically grant unrestricted access.

### Q2. Why is MFA so effective, and which attacks does it defeat?

MFA requires independent evidence from more than one factor class. A password is something the user knows, while the TOTP generator or authenticator is something the user possesses. A stolen password alone is therefore insufficient. MFA is effective against password guessing, credential stuffing, password reuse, brute-force password attacks, and many attacks based on leaked or phished passwords. TOTP is not a complete defence against real-time adversary-in-the-middle phishing or MFA-fatigue techniques, so phishing-resistant factors are preferable for higher-risk systems.

### Q3. How does network segmentation limit the damage of a compromised web server?

Segmentation places the public-facing web tier and the database on different networks. In this lab, `web` had access only to `frontend-net`, while `db` had access only to `backend-net`; only `app` joined both. If an attacker compromises the web server, the attacker still has no direct network path to Redis. This limits lateral movement, reduces the reachable attack surface, and forces database access through the controlled application tier.

### Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?

A default-deny policy drops traffic unless a rule explicitly permits it. The lab's `INPUT DROP` policy allowed only HTTPS on TCP port `443` and loopback traffic. This reduces accidental exposure and makes each permitted path deliberate. Cloud security groups use the same allow-list principle: inbound traffic is denied unless an ingress rule explicitly allows a protocol, port, and source.

### Q5. List the hardening measures applied and the attack surface each one removes.

The core measures were running as a non-root user, mounting the root filesystem read-only, and dropping all Linux capabilities. These controls respectively reduce privilege after service compromise, block filesystem tampering and persistence, and remove access to privileged kernel operations. The container also used `no-new-privileges` to prevent privilege gains and a `tmpfs` mount for non-persistent temporary writes. Finally, an Alpine-based Nginx image was scanned with Trivy to identify known high- and critical-severity package vulnerabilities.

## Security best-practices checklist

- [x] Service requires authentication; unauthenticated requests are rejected.
- [x] MFA/second factor was generated and successfully validated.
- [x] RBAC enforces least privilege; unauthorized actions are denied.
- [x] Network segmentation prevents direct web-to-database communication.
- [x] Default-deny firewall uses explicit allow rules.
- [x] Container runs as non-root.
- [x] Container root filesystem is read-only.
- [x] Linux capabilities are dropped.
- [x] `no-new-privileges` is enabled.
- [x] Image was scanned for high- and critical-severity vulnerabilities.

## Cleanup and teardown

The lab resources were removed after evidence collection.

```bash
docker rm -f authsvc db app web hardened 2>/dev/null
docker network rm frontend-net backend-net 2>/dev/null
kind delete cluster --name ccse-lab4
```

The cleanup output shows removal of the remaining containers, both custom networks, and the `ccse-lab4` kind cluster. `authsvc` had already been stopped earlier and was automatically removed because it was started with `--rm`.

![Cleanup and teardown output](lab-images/lab4/cleanup.png)

## Evidence completeness and issues found

All required deliverables from the guide are present:

| Guide requirement | Evidence | Status |
|---|---|---:|
| HTTP `401` without credentials and `200` with valid credentials | Task 1 authentication screenshot | Complete |
| Valid TOTP produces `MFA OK` | Task 2 screenshot | Complete |
| Three `kubectl auth can-i` results | Task 3 RBAC screenshot | Complete |
| `web -> db: BLOCKED` and `app -> db: REACHABLE` | Task 4 results screenshot | Complete |
| Default-deny iptables ruleset | Task 5 screenshot | Complete |
| Hardened-container inspect output | Task 6 inspect screenshot | Complete |
| Trivy scan summary | Task 6 Trivy summary screenshot | Complete |
| Role-binding YAML verification | Task 3 RBAC screenshot | Complete |
| Dropped-capabilities verification | Task 6 inspect screenshot | Complete |

### Missing or noteworthy items

- No required step, picture, or command output is missing.
- The workspace originally had no folder named `Evidence`; the 13 source screenshots were stored at the workspace root. This report creates and uses an `lab-images/lab4/` folder with clearly named copies.
- Task 2 contains an initial `MFA FAILED` result, followed by the required successful `MFA OK` result using a fresh code. No repeat screenshot is needed.
- Task 4 contains a duplicate `web` container-name warning. The following container list and the final connectivity tests confirm that the required container was already running, so no evidence is missing.
- The Trivy result is time-specific and covers only the requested `HIGH` and `CRITICAL` severities for `nginx:alpine`; it should not be interpreted as proof that no lower-severity or future vulnerability exists.

## Conclusion

The lab successfully combined identity controls, authorization, network controls, and workload hardening. Password authentication rejected anonymous access; TOTP added a second factor; Kubernetes RBAC enforced least privilege; Docker segmentation blocked direct frontend-to-database access; the firewall denied traffic by default; and the hardened container ran non-root with a read-only filesystem, no added capabilities, and no privilege escalation. The accompanying Trivy scan reported zero high- or critical-severity vulnerabilities for the scanned Alpine Nginx image at the time of testing.
