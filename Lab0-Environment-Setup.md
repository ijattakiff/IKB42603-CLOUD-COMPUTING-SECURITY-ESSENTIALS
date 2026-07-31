# Lab 0: Environment Setup Report

## Course Information

**Course:** IKB42603 Cloud Computing Security Essentials  
**Lab:** Lab 0 - Environment Setup   
**Name:** Student name 
<br> **Date:** 27 July 2026  

## Objective

The objective of this setup is to prepare the local lab environment required before Lab 1. Based on the setup cheatsheet, the environment must support Docker, AWS CLI v2, kind, kubectl, OpenSSL, oathtool, LocalStack, and a local Kubernetes cluster.

All services are intended to run locally. LocalStack is used as the local AWS simulator, and kind is used to run Kubernetes inside Docker.

## Environment Summary

Evidence is provided for both the Mac environment and the Kali environment.

| Component | Mac Verified Version / Status | Mac Proof | Kali Verified Version / Status | Kali Proof |
| --- | --- | --- | --- | --- |
| Docker | Docker version 29.6.1 | `Evidence/1.docker.png` | Docker version 28.5.2 | `Evidence/kali/1.docker.png` |
| AWS CLI | aws-cli/2.36.8 | `Evidence/2.awscli.png` | aws-cli/2.36.9 | `Evidence/kali/2.awscli.png` |
| kind | kind v0.32.0 | `Evidence/3.kind_kubectl.png` | kind v0.32.0 | `Evidence/kali/3.1-kind.png` |
| kubectl | Client version v1.36.1, Kustomize v5.8.1 | `Evidence/3.kind_kubectl.png` | Client version v1.33.4, Kustomize v5.5.0 | `Evidence/kali/3.kubectl.png` |
| OpenSSL | OpenSSL 3.6.3 | `Evidence/4.Helper_tools.png` | OpenSSL 3.5.4 | `Evidence/kali/4.Helper.png` |
| oathtool | OATH Toolkit 2.6.14 | `Evidence/4.Helper_tools.png` | OATH Toolkit 2.6.14 | `Evidence/kali/4.Helper.png` |
| LocalStack | Running and healthy on port 4566 | `Evidence/5.localstack.png` | Running and healthy on port 4566 | `Evidence/kali/5.localstack.png` |
| Kubernetes | kind cluster `ccse` running with node `ccse-control-plane` ready | `Evidence/5.1.kubenetes.png` | kind cluster `ccse` running with node `ccse-control-plane` ready | `Evidence/kali/5.1.kubenetes.png` |
| AWS CLI LocalStack endpoint | Dummy credentials and endpoint variable configured | `Evidence/6.one-time.png` | Dummy credentials configured and STS caller identity tested through LocalStack | `Evidence/kali/6-config.png` |

## Step 1: Install and Verify Docker

Docker is required to run containers, LocalStack, and the kind Kubernetes cluster.

According to the guide, Docker Desktop should be installed on Windows or macOS. On Linux, Docker can be installed using the official convenience script:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

After installation, Docker was verified with:

```bash
docker --version
```

The Mac proof shows Docker version `29.6.1`, build `8900f1d`.

<img width="646" height="81" alt="1 docker" src="https://github.com/user-attachments/assets/37dd09a8-cee1-4347-8d87-dd8bf0f629a3" />

The Kali proof shows Docker version `28.5.2`.

<img width="729" height="69" alt="1 docker" src="https://github.com/user-attachments/assets/c843bbee-6aac-4e9d-8a58-7dc4bf0c55f2" />

The guide also recommends confirming Docker can run containers with:

```bash
docker run --rm hello-world
```

## Step 2: Install and Verify AWS CLI v2

AWS CLI v2 is required to send AWS-style commands to LocalStack during the labs.

The guide provides these installation options:

| Operating System | Installation Method |
| --- | --- |
| Windows | Download and run the AWS CLI v2 MSI installer from AWS |
| macOS | Install using `brew install awscli` or the AWS `.pkg` installer |
| Linux | Download and install the AWS CLI v2 ZIP package |

Linux installation command from the guide:

```bash
curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o awscliv2.zip
unzip awscliv2.zip && sudo ./aws/install
```

AWS CLI was verified with:

```bash
aws --version
```

The Mac proof shows AWS CLI version `2.36.8`.

<img width="639" height="61" alt="2 awscli" src="https://github.com/user-attachments/assets/a381d0ec-e0b2-4727-badd-b3e2f03b4fef" />


The Kali proof shows AWS CLI version `2.36.9`.

<img width="714" height="76" alt="2 awscli" src="https://github.com/user-attachments/assets/5905bbe6-f23b-4cab-858e-88d5bbabcfee" />

No real AWS account is required for this lab because AWS CLI commands are pointed to LocalStack.

## Step 3: Install and Verify kind and kubectl

kind is used to create a local Kubernetes cluster inside Docker. kubectl is used to interact with the Kubernetes cluster.

The guide provides these installation options:

| Operating System | kind | kubectl |
| --- | --- | --- |
| Windows | `choco install kind` | `choco install kubernetes-cli` |
| macOS | `brew install kind` | `brew install kubectl` |
| Linux | Download the kind binary | `sudo snap install kubectl --classic` |

Linux kind installation command from the guide:

```bash
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind
```

The tools were verified with:

```bash
kind --version
kubectl version --client
```

The Mac proof shows:

- kind version `0.32.0`
- kubectl client version `v1.36.1`
- Kustomize version `v5.8.1`

<img width="372" height="73" alt="3 kind_kubectl" src="https://github.com/user-attachments/assets/5fdd5883-97e1-46ad-b8cc-6f011b217d45" />

The Kali proof shows:

- kind version `0.32.0`
- kubectl client version `v1.33.4`
- Kustomize version `v5.5.0`

<img width="281" height="124" alt="3 kubectl" src="https://github.com/user-attachments/assets/aaed1ba6-5da6-41f7-86c9-f167657a579b" />
<img width="213" height="64" alt="3 1-kind" src="https://github.com/user-attachments/assets/b4b81d4f-ba9a-4708-bfc1-7f148d897ee6" />

## Step 4: Install and Verify Helper Tools

The guide lists helper tools used in later labs:

| Tool | Purpose |
| --- | --- |
| OpenSSL | Encryption, keys, and certificates |
| oathtool | MFA / TOTP code generation |
| Trivy | Container vulnerability scanning, run through Docker in Lab 4 |

The tools were verified with:

```bash
openssl version
oathtool --version
```

The Mac proof shows:

- OpenSSL `3.6.3`
- oathtool / OATH Toolkit `2.6.14`

<img width="1191" height="147" alt="4 Helper_tools" src="https://github.com/user-attachments/assets/41450a83-e696-482a-90a7-ab4a0f333263" />

The Kali proof shows:

- OpenSSL `3.5.4`
- oathtool / OATH Toolkit `2.6.14`

<img width="767" height="225" alt="4 Helper" src="https://github.com/user-attachments/assets/ab5ee65a-285b-4074-bf6f-0dff1ba4ba15" />

Trivy does not require a separate installation for this setup because the guide runs it through Docker:

```bash
docker run --rm aquasec/trivy image <name>
```

## Step 5: Start and Verify LocalStack

LocalStack provides a local AWS-compatible environment for the labs.

The guide starts LocalStack with:

```bash
docker run -d --name localstack -p 4566:4566 localstack/localstack
```

In this setup, the evidence shows LocalStack running with the pinned image `localstack/localstack:3.0`:

```bash
docker run -d --name localstack -p 4566:4566 -p 4510-4559:4510-4559 localstack/localstack:3.0
```

LocalStack was checked with:

```bash
curl http://localhost:4566/_localstack/health
docker ps
```

The health endpoint returned available services, and `docker ps` showed the LocalStack container running with a healthy status on port `4566`.

<img width="1280" height="164" alt="5 localstack" src="https://github.com/user-attachments/assets/d5d11631-185a-45aa-b216-40069d216fbe" />

The Kali proof shows the `localstack/localstack:3.0` container running with a healthy status and port `4566` mapped.

<img width="1493" height="165" alt="5 localstack" src="https://github.com/user-attachments/assets/29649b39-b099-427a-9185-3d83407240b8" />

Useful LocalStack lifecycle commands from the guide:

```bash
docker stop localstack
docker start localstack
docker rm -f localstack
```

## Step 6: Create and Verify the Kubernetes Cluster

The guide creates a local kind cluster named `ccse`:

```bash
kind create cluster --name ccse
```

The cluster was verified with:

```bash
kubectl cluster-info --context kind-ccse
kubectl get nodes
```

The Mac proof confirms:

- Kubernetes control plane is running on `127.0.0.1`
- CoreDNS is running
- Node `ccse-control-plane` is `Ready`
- Kubernetes version is `v1.36.1`

<img width="1147" height="135" alt="5 1 kubenetes" src="https://github.com/user-attachments/assets/f9eab168-faed-420b-9dcf-ceed899e429d" />

The Kali proof confirms the same `ccse` kind cluster status, with node `ccse-control-plane` in the `Ready` state.

<img width="1147" height="135" alt="5 1 kubenetes" src="https://github.com/user-attachments/assets/02eecdcc-9f0d-4f7e-ac87-71045efce38f" />

The guide removes the cluster with:

```bash
kind delete cluster --name ccse
```

## Step 7: Configure AWS CLI for LocalStack

LocalStack accepts dummy credentials, so the AWS CLI was configured with test values:

```bash
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1
```

The guide recommends saving the LocalStack endpoint in a variable for each terminal session:

```bash
EP='--endpoint-url=http://localhost:4566'
aws $EP sts get-caller-identity
```

The Mac proof shows the dummy AWS CLI values configured and the endpoint variable set:

```bash
EP='--endpoint-url=http://localhost:4566'
```

<img width="1151" height="63" alt="6 one-time" src="https://github.com/user-attachments/assets/c0f074e5-686b-4ffb-b9be-1babd85b8953" />

The Kali proof shows the dummy credentials configured, the endpoint variable set, and `aws $EP sts get-caller-identity` returning a LocalStack test identity.

<img width="469" height="307" alt="6-config" src="https://github.com/user-attachments/assets/009166ad-cb36-4cc5-b0ee-34d5c2852184" />

This ensures AWS CLI commands target LocalStack instead of real AWS services.

## Pre-Lab Verification Checklist

| Check | MacOS | Kali OS |
| --- | --- | --- |
| `docker --version` prints a version | Completed | Completed |
| `aws --version` prints AWS CLI v2 | Completed | Completed |
| `kind --version` works | Completed | Completed |
| `kubectl version --client` works | Completed | Completed |
| `openssl version` works | Completed | Completed |
| `oathtool --version` works | Completed | Completed |
| LocalStack health endpoint responds | Completed | Completed |
| Kubernetes cluster `ccse` is running | Completed | Completed |
| `kubectl get nodes` shows a ready node | Completed | Completed |
| AWS CLI dummy credentials are configured | Completed | Completed |
| LocalStack endpoint variable is configured | Completed | Completed |

## Troubleshooting Notes from the Guide

| Symptom | Recommended Fix |
| --- | --- |
| Cannot connect to Docker daemon | Start Docker Desktop or re-login after adding the Linux user to the `docker` group |
| Docker will not start | Enable hardware virtualization in BIOS/UEFI; on Windows enable WSL 2 and Virtual Machine Platform |
| Port `4566` already in use | Remove the existing LocalStack container with `docker rm -f localstack` and start it again |
| AWS CLI cannot connect to endpoint URL | Start LocalStack and make sure `--endpoint-url=http://localhost:4566` or `$EP` is used |
| `aws`, `kind`, or `kubectl` command not found | Reinstall the tool and open a new terminal so PATH updates are loaded |
| kind cluster creation fails | Make sure Docker is running and has enough memory allocated |
| MFA / TOTP code fails in later labs | Enable automatic system time synchronization |

## Conclusion

The Lab 0 environment setup was completed successfully on both Mac and Kali. Docker, AWS CLI v2, kind, kubectl, OpenSSL, oathtool, LocalStack, and the local kind Kubernetes cluster were installed and verified. The environments are ready for the next IKB42603 Cloud Computing Security Essentials lab activities using LocalStack and Kubernetes.
