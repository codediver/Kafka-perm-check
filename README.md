# kafka-perm-check

A single-binary CLI tool for verifying Kafka ACL permissions across topics, consumer groups, transactional IDs, and Schema Registry subjects.

---

> **⚠️ topic:WRITE produces a real record**
>
> The Kafka protocol has no dry-run produce — the only way to verify WRITE permission is to attempt an actual produce request. `topic:WRITE` produces one small sentinel record that is permanently committed to the topic.
>
> **Do not run `topic:WRITE` against production topics.** Use a dedicated canary topic with a short retention period, or skip the check entirely with `--skip-topic` / use `--skip-topic` and rely on `txn:WRITE (aborted)` if your principal has transactional ACLs.

---

## What it checks

| Resource | Check | Method | Side effects |
|---|---|---|---|
| Topic | `DESCRIBE` | Admin DescribeTopicConfigs | None |
| Topic | `READ` | Subscribe at end offset, poll once — no commit | None |
| Topic | `WRITE` | Produce one sentinel record | **Record written permanently** |
| Consumer Group | `DESCRIBE` | Admin DescribeGroups | None |
| Consumer Group | `READ` | Join group at latest offset, poll, clean leave | None |
| Consumer Group | `OFFSET_READ` | Admin FetchOffsets — no reset | None |
| Transactional ID | `WRITE (aborted)` | Begin → produce → AbortTransaction | None — transaction aborted, no consumer-visible record |
| Schema Registry | `READ` | GET /subjects/{subject}/versions | None |

Exit code `0` if all checks pass. Exit code `1` if any check is DENIED or ERRORED.

---

## Install

### Build from source

```sh
git clone https://github.com/yourorg/kafka-perm-check
cd kafka-perm-check
go build -o kafka-perm-check .
```

Or cross-compile for all platforms:

```sh
make dist   # outputs to ./dist/
```

---

## Configuration

All Kafka client config (brokers, auth, TLS) is read from a properties file. Copy the example and fill in your values:

```sh
cp kafka.properties.example kafka.properties
```

The default path is `kafka.properties` in the working directory. Override with `--config`.

### Security protocol

```properties
# PLAINTEXT | SSL | SASL_PLAINTEXT | SASL_SSL
security.protocol=SASL_SSL
```

### Authentication

**PLAIN / SCRAM**
```properties
sasl.mechanism=PLAIN          # or SCRAM-SHA-256 / SCRAM-SHA-512
sasl.username=myuser
sasl.password=mypassword
```

**OAuthBearer** (client credentials grant)
```properties
sasl.mechanism=OAUTHBEARER
sasl.oauthbearer.token.endpoint.url=https://auth.example.com/oauth/token
sasl.oauthbearer.client.id=my-client-id
sasl.oauthbearer.client.secret=my-client-secret
sasl.oauthbearer.scope=kafka   # optional
sasl.oauthbearer.extensions.logicalCluster=lkc-xxxxx    # optional, Confluent Cloud
sasl.oauthbearer.extensions.identityPoolId=pool-xxxxx   # optional, Confluent Cloud
```

### Kafka TLS

Truststore and keystore accept **JKS or PKCS12** — format is detected automatically. Truststore/keystore take precedence over PEM files when both are configured.

**One-way TLS — truststore**
```properties
ssl.truststore.location=/path/to/kafka.truststore.jks
ssl.truststore.password=truststorepass
```

**mTLS — add keystore**
```properties
ssl.keystore.location=/path/to/kafka.keystore.jks
ssl.keystore.password=keystorepass
ssl.key.password=keypassphrase   # private key entry password; defaults to keystore password if unset
```

**PEM alternative** (used when no truststore/keystore is set)
```properties
ssl.ca.location=/path/to/ca.pem
ssl.certificate.location=/path/to/client.pem
ssl.key.location=/path/to/client.key
ssl.key.password=keypassphrase
```

Disable hostname verification (not recommended for production):
```properties
ssl.endpoint.identification.algorithm=
```

### Schema Registry TLS

Schema Registry has its own independent TLS config, also accepting JKS or PKCS12.

```properties
schema.registry.url=https://sr.example.com

# One-way TLS
schema.registry.ssl.truststore.location=/path/to/sr.truststore.jks
schema.registry.ssl.truststore.password=truststorepass

# mTLS
schema.registry.ssl.keystore.location=/path/to/sr.keystore.jks
schema.registry.ssl.keystore.password=keystorepass
```

### Schema Registry auth

Auth priority: basic auth > SR bearer auth > inherit Kafka OAUTHBEARER.

```properties
# Basic auth (highest priority)
schema.registry.basic.auth.user.info=myuser:mypassword

# Bearer auth — SR-specific OAuth/OIDC
# Falls back to sasl.oauthbearer.* if issuer/client settings are omitted.
bearer.auth.credentials.source=OAUTHBEARER            # OAUTHBEARER (default) or STATIC_TOKEN
bearer.auth.issuer.endpoint.url=https://auth.example.com/oauth/token
bearer.auth.client.id=sr-client-id
bearer.auth.client.secret=sr-client-secret
bearer.auth.scope=schema-registry                      # optional
bearer.auth.logical.cluster=lsrc-xxxxx                 # optional, Confluent Cloud
bearer.auth.identity.pool.id=pool-xxxxx                # optional, Confluent Cloud

# OAuthBearer — automatic when sasl.mechanism=OAUTHBEARER and no basic/bearer auth is set
```

---

## Usage

```
kafka-perm-check [flags]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--config` | `kafka.properties` | Path to client properties file |
| `--timeout` | `10` | Per-operation timeout in seconds |
| `--topic` | | Topic to test (DESCRIBE, READ, WRITE) |
| `--group` | | Consumer group to test (DESCRIBE, READ, OFFSET_READ) |
| `--txn-id` | | Transactional ID to test (WRITE + abort) |
| `--sr-subject` | | Schema Registry subject to test READ on |
| `--skip-topic` | | Skip topic checks |
| `--skip-group` | | Skip consumer group checks |
| `--skip-txn` | | Skip transactional ID checks |
| `--skip-schema` | | Skip Schema Registry checks |

### Examples

**Full check with OAuthBearer + mTLS**
```sh
kafka-perm-check \
  --config kafka.properties \
  --topic payments \
  --group payments-consumer \
  --txn-id payments-producer-txn \
  --sr-subject payments-value
```

**Schema Registry only**
```sh
kafka-perm-check \
  --config kafka.properties \
  --skip-topic --skip-group --skip-txn \
  --sr-subject payments-value
```

**CI pipeline**
```sh
kafka-perm-check --config kafka.properties --topic "$TOPIC" --group "$GROUP" \
  && echo "ACLs OK" \
  || { echo "ACL check failed"; exit 1; }
```

### Sample output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  kafka-perm-check
  config  : kafka.properties
  brokers : broker1:9092, broker2:9092
  auth    : OAUTHBEARER (client_id=my-client-id)
  tls     : mTLS
  sr      : https://sr.example.com  auth=basic (myuser) mTLS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

── Topic: payments
  ✅  topic:DESCRIBE                               metadata readable
  ✅  topic:READ                                   fetch issued successfully (no new records in poll window)
  ✅  topic:WRITE                                  message delivered

── Consumer Group: payments-consumer
  ✅  group:DESCRIBE                               group metadata readable
  ✅  group:READ                                   joined group successfully (no new records in poll window)
  ✅  group:OFFSET_READ (dry)                      committed offsets readable

── Transactional ID: payments-producer-txn
  ✅  txn:WRITE (aborted)                          transaction initiated and aborted (no data committed)

── Schema Registry Subject: payments-value
  ✅  schema:READ                                  versions listed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✅ 8 passed   ❌ 0 denied   ⚠️  0 errors   ⏭  0 skipped
```

---

## Dependencies

| Library | Purpose |
|---|---|
| [`twmb/franz-go`](https://github.com/twmb/franz-go) | Pure-Go Kafka client (no CGo — enables static binaries) |
| [`spf13/cobra`](https://github.com/spf13/cobra) | CLI flag parsing |
| [`pavlo-v-chernykh/keystore-go`](https://github.com/pavlo-v-chernykh/keystore-go) | JKS keystore parsing |
| [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) | PKCS12 keystore parsing |
