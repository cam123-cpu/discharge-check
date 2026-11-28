# Deploying Discharge Check on AWS

This guide covers a production-shaped deployment on AWS for a hospital pilot.
It assumes the container image from this repo, which runs uvicorn as a non-root
user on port 8000, serves `GET /healthz`, and runs with a read-only root file
system. It does not create anything for you. Every step here is a decision for
the team that owns the AWS account.

**Use synthetic data only until every item in the go-live checklist is done.**

## 1. Before you start

- Sign the AWS Business Associate Addendum (BAA) in AWS Artifact for the
  account, or for the whole Organization, that will hold PHI.
- Sign a BAA with Anthropic before you set `ANTHROPIC_API_KEY` in any
  environment that holds real PHI. Without that BAA, leave the key unset. The
  built-in pattern rules still run.
- Use only HIPAA-eligible services for anything that stores, processes or
  transmits PHI. Check every service in this guide against the current AWS
  HIPAA Eligible Services Reference before you use it. The list changes.
- Use a dedicated AWS account for this app, under AWS Organizations. Keep
  development and production in separate accounts.
- Turn on, at the Organization level:
  - a CloudTrail organization trail, logging to a separate log-archive account;
  - GuardDuty in every region you use;
  - Security Hub, with the AWS Foundational Security Best Practices standard
    and any HIPAA-oriented standard or conformance pack it currently offers;
  - AWS Config recording all resources, with the HIPAA Security conformance
    pack if it is available to you.

## 2. Architecture

```
 Users (hospital network / internet)
        |
   Route 53 (DNS)
        |
   AWS WAF  ── managed rule groups + rate-based rule
        |
   Application Load Balancer  (public subnets, ACM cert, TLS 1.2+ policy,
        |                      HTTP:80 -> HTTPS:443 redirect)
        |  HTTP:8000
   ECS Fargate service  (private subnets, no public IP, non-root, read-only fs)
        |            \
        |             VPC endpoints: ECR (api, dkr), S3 (gateway),
        |             Secrets Manager, CloudWatch Logs, KMS
        |
   RDS PostgreSQL  (private subnets, Multi-AZ, CMK-encrypted, rds.force_ssl=1)

   Optional: NAT gateway -> api.anthropic.com only (model review on)
```

- **Route 53** holds the DNS record for the app's domain.
- **Application Load Balancer** in public subnets. Use an ACM certificate and
  a TLS security policy that allows TLS 1.2 and 1.3 only. Add an HTTP listener
  whose only action is a redirect to HTTPS. Turn on ALB access logs to an
  encrypted S3 bucket.
- **AWS WAF** on the ALB with the AWS managed Core rule set, Known bad inputs
  and IP reputation rule groups, plus a rate-based rule on `/login` and a
  general one per source IP. Remember that a hospital puts many users behind
  one IP; set the general limit with that in mind.
- **ECS Fargate** service in private subnets with `assignPublicIp: DISABLED`.
  The task security group accepts port 8000 from the ALB security group only.
- **RDS for PostgreSQL** is the target data store. Encrypt it with a
  customer-managed KMS key, run Multi-AZ, keep automated backups on, turn on
  deletion protection, and set `rds.force_ssl = 1` in the parameter group so
  every connection must use TLS. The security group accepts 5432 from the task
  security group only. The move from SQLite to Postgres with row-level security
  is in progress; do not pilot with real PHI before it lands.
- **SQLite on EFS (pilot stopgap only).** Until Postgres lands, you can mount an
  encrypted EFS access point at `/data` and set `DATABASE_PATH=/data/app.db`.
  Run exactly one task (desired count 1, max 1, deployment minimum 0 percent)
  because SQLite locking over a network file system is not reliable with more
  than one writer. Expect a short outage on every deploy.
- **VPC endpoints** for ECR (`ecr.api`, `ecr.dkr`), S3 (gateway endpoint, used
  by ECR layers), Secrets Manager, CloudWatch Logs and KMS. With these, tasks
  need no NAT gateway. If model review is on, add a NAT gateway and restrict
  egress to the Anthropic API with AWS Network Firewall domain rules or an
  egress proxy. A security group cannot filter by host name.

## 3. Secrets management

Store each secret in AWS Secrets Manager, encrypted with a customer-managed KMS
key used only for this app:

| Secret | What it does | Rotation |
| --- | --- | --- |
| `DATA_KEY` | Fernet key that encrypts document text and results at rest | Supported: `DATA_KEY_PREVIOUS` plus `scripts.rotate_data_key` ([key-rotation.md](key-rotation.md)) |
| `SESSION_PEPPER` | Keys session token hashes and signed cookies | Rotate any time; every user is signed out |
| `AUDIT_KEY` | HMAC key for the hash-chained audit log | Supported: `AUDIT_KEY_PREVIOUS`; keep old keys as long as their rows ([key-rotation.md](key-rotation.md)) |
| `ANTHROPIC_API_KEY` | Model review (optional) | Rotate in the Anthropic console, then update the secret and redeploy |

Generate keys offline, on a trusted machine, and paste them straight into
Secrets Manager:

```bash
# DATA_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# SESSION_PEPPER and AUDIT_KEY (one run each)
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

- Inject secrets through the task definition's `secrets` block, with
  `valueFrom` set to the secret ARN. They then never appear in the image, in an
  env file, or as plaintext in the task definition. Do not use `environment`
  for any of them.
- The task execution role may call `secretsmanager:GetSecretValue` on those
  four ARNs only, and `kms:Decrypt` on that one key only.
- Set `AUDIT_KEY` explicitly in production. If it is unset the app derives it
  from `DATA_KEY`, which ties two keys together.
- **Back up `DATA_KEY` separately.** If it is lost, every stored record is
  unreadable and cannot be recovered. Keep a break-glass copy outside AWS (for
  example, sealed and split between two officers, or in a separate vault),
  and test once that the copy decrypts a restored database.
- Turn on deletion protection for the KMS key (a pending-deletion alarm) and
  use the maximum recovery window on the secrets.
- Never store AWS or app secrets in GitHub Actions. CI needs no AWS secrets.
  If you add a deploy pipeline later, authenticate it with GitHub OIDC to an
  IAM role whose trust policy is pinned to this repository and branch.

## 4. App configuration in AWS

Plain environment variables (not secret):

```
FORCE_HTTPS=1
ALLOWED_HOSTS=discharge.example-hospital.org
DATABASE_PATH=/data/app.db        # SQLite stopgap only
```

- The image already starts uvicorn with `--proxy-headers`. Set the
  `FORWARDED_ALLOW_IPS` environment variable (uvicorn reads it) to
  `127.0.0.1,<ALB subnet CIDRs>`, for example `127.0.0.1,10.0.0.0/16`. The
  ALB's addresses change, so a single IP does not work, and keep `127.0.0.1`
  because the container's own health check relies on it. With this, the app
  sees the real scheme (`https`) and the access log and rate limits see the
  real client IP.
- The ALB target group uses HTTP to port 8000 and health check path `/healthz`.
  ALB health checks send `Host: <task IP>:8000` over plain HTTP. The app answers
  exactly `GET`/`HEAD /healthz` before the host check and the HTTPS redirect,
  so these probes pass while every other path stays protected. ECS ignores the
  Dockerfile `HEALTHCHECK`; define one in the task definition if you want a
  container-level check.
- Mount `/data` (EFS, stopgap only) and a small writable `tmpfs` if the app
  needs scratch space, since the root file system is read-only.

## 5. Logging, audit and retention

- Send container logs to CloudWatch Logs with the `awslogs` driver. Encrypt the
  log group with a KMS key.
- Keep audit-related logs for at least 6 years. HIPAA (45 CFR 164.316(b)(2))
  requires keeping required documentation for 6 years; many organizations
  apply the same period to audit logs. Confirm the period with your compliance
  officer. The `audit_log` table in the database is the primary access record;
  database backups and archives must follow the same retention.
- **No PHI in application logs.** The app logs error types and paths, not
  record text. Keep it that way in code review, and do not turn on request body
  logging anywhere (ALB, WAF full logs, or debug middleware).
- **Daily chain check.** Run `python -m scripts.verify_audit` as a scheduled ECS
  task (EventBridge Scheduler, same task definition and secrets). It exits 0
  when the chain is intact and 1 when it is not. Alarm on a non-zero exit or a
  missed run (EventBridge task state change to an SNS topic).
- **Anchor the chain head.** In the same job, run
  `python -m scripts.verify_audit --head` and write its JSON (`{id, row_hash}`)
  to an S3 bucket with Object Lock in compliance mode and a retention of at
  least 6 years. The database triggers block UPDATE and DELETE on `audit_log`,
  but someone with database owner rights could still rebuild or truncate it.
  The anchored heads make that detectable: every stored head must still appear
  in the chain with the same hash.
- Turn on CloudTrail S3 data events for the anchor bucket, so every write and
  read attempt is recorded.

## 6. Backups and disaster recovery

- RDS automated backups with a retention period your policy sets (up to 35
  days), plus scheduled snapshots kept longer with AWS Backup.
- Copy snapshots to a second region, re-encrypted with a KMS key in that
  region. Put the backup vault under AWS Backup Vault Lock if your policy
  needs immutable backups.
- For the SQLite stopgap, back up the EFS file system with AWS Backup.
- A backup is useless without `DATA_KEY`. Confirm the break-glass copy is part
  of the DR runbook.
- Test a full restore every quarter: restore to a new instance, start the app
  against it, run `python -m scripts.verify_audit`, and record the time taken.
- Targets: RPO = `____` hours, RTO = `____` hours. Set these with the hospital
  before go-live.

## 7. Access control

- People sign in to AWS through IAM Identity Center with MFA required. No IAM
  users with long-lived access keys.
- Keep one break-glass account with a hardware MFA key, its credentials
  stored offline, and an alarm on every sign-in.
- The task role (what the app itself can call) needs no AWS API access. Leave
  it empty, except what the scheduled audit job needs to write to the anchor
  bucket (`s3:PutObject` on that bucket's prefix only). The execution role
  holds only ECR pull, log writes, and the secret reads above.
- Disable ECS Exec in production. If you must enable it for an incident, turn
  on session logging to an encrypted log group and S3, and record why.
- Database access for people goes through IAM database authentication or a
  short-lived credential from Secrets Manager, never a shared password.

## 8. Go-live checklist

- [ ] AWS BAA signed in AWS Artifact for this account
- [ ] BAA with Anthropic signed, or `ANTHROPIC_API_KEY` unset in production
- [ ] BAA (or agreement) with the hospital in place
- [ ] Every service in use checked against the current HIPAA-eligible list
- [ ] Postgres with row-level security deployed (SQLite stopgap retired)
- [ ] Secrets in Secrets Manager with a CMK; none in the image, env files or CI
- [ ] `DATA_KEY` break-glass copy stored and tested
- [ ] `/healthz` passes ALB health checks with `FORCE_HTTPS=1` and `ALLOWED_HOSTS` set
- [ ] Client IPs in the access log are real user IPs, not ALB addresses
- [ ] Daily `verify_audit` job running, alarm tested by a forced failure
- [ ] Audit chain heads landing in the Object Lock bucket
- [ ] Log retention set to at least 6 years for audit-related logs
- [ ] Cross-region snapshot copy working; one restore test done
- [ ] Penetration test of the deployed environment, findings fixed
- [ ] Risk analysis done and documented (45 CFR 164.308(a)(1)(ii)(A))
- [ ] MFA or SSO for app users (not built yet; see gaps)
- [ ] Incident response and breach notification runbook written
- [ ] Synthetic data only until every box above is checked

## 9. Known gaps in the app

- No multi-factor sign-in and no SSO for app users. This is the largest gap
  for a pilot with real PHI.
- SQLite storage. Postgres with row-level security is in progress.
- The `/healthz` route must pass the host and HTTPS checks (section 4).
- Model review has been tested only with a stubbed client. Measure prompt
  injection resistance against the live model before enabling it.
- No accuracy measurement per rule yet.
- No EHR integration. Privacy and Terms pages are drafts.
- The PHI screen on upload is a guard rail, not de-identification.
