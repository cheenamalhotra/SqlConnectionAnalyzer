# How a SQL Server login actually works

A beginner's walkthrough of what `SqlConnection.Open()` does between the moment you call it and
the moment you can run a query.

The goal is to explain **why connection failures happen where they do**. Every step below is a
place a connection can break, and each one breaks for different reasons and needs a different fix.

**Contents**

- [The short version](#the-short-version)
- [Step 1: Read the connection string](#step-1-read-the-connection-string)
- [Step 2: Find the server](#step-2-find-the-server)
- [Step 3: Connect over TCP](#step-3-connect-over-tcp)
- [Step 4: Agree on the rules (PRELOGIN)](#step-4-agree-on-the-rules-prelogin)
- [Step 5: Turn on encryption (TLS)](#step-5-turn-on-encryption-tls)
- [Step 6: Prove who you are](#step-6-prove-who-you-are)
- [Step 7: The session opens](#step-7-the-session-opens)
- [Two failures that are not really login](#two-failures-that-are-not-really-login)
- [Where each failure lands](#where-each-failure-lands)
- [Glossary](#glossary)

---

## The short version

Opening a SQL connection is not one action. It is seven, and they always happen in this order.

```mermaid
%%{init: {"htmlLabels": false, "flowchart": {"htmlLabels": false}} }%%
flowchart TB
    accTitle: The seven stages of a SQL Server login
    accDescr {
        Seven stages run in a fixed order, laid out across two rows. Read the connection
        string, find the
        server, connect over TCP, negotiate PRELOGIN, perform the TLS handshake, prove
        your identity, and finally open the session. Each stage runs only if the previous
        one succeeded.
    }

    subgraph row1[" "]
        direction LR
        A["1. Read the<br/>connection string"] --> B["2. Find the<br/>server"]
        B --> C["3. Connect<br/>over TCP"]
        C --> D["4. Negotiate<br/>PRELOGIN"]
    end
    subgraph row2[" "]
        direction LR
        E["5. TLS<br/>handshake"] --> F["6. Prove who<br/>you are"]
        F --> G["7. Session<br/>ready"]
    end
    D --> E

    style row1 fill:none,stroke:none
    style row2 fill:none,stroke:none

    classDef setup fill:#dbeafe,stroke:#1e40af,stroke-width:1px,color:#111827
    classDef negotiate fill:#fef3c7,stroke:#92400e,stroke-width:1px,color:#111827
    classDef secure fill:#ede9fe,stroke:#5b21b6,stroke-width:1px,color:#111827
    classDef done fill:#dcfce7,stroke:#166534,stroke-width:2px,color:#111827

    class A,B,C setup
    class D,E negotiate
    class F secure
    class G done
```

The single most useful idea in this whole document:

> **Each step runs only if the one before it succeeded.**
> So "login failed" almost never means "wrong password". It means *whichever step broke first*.
> Finding that step is the entire job.

The rules these steps follow are called **TDS** (Tabular Data Stream), Microsoft's wire format for
SQL Server. It is publicly documented as MS-TDS.

---

## The conversation, end to end

Two diagrams follow. The first covers getting a secure channel open. The second covers proving
who you are. They are split deliberately — the whole exchange in one picture is hard to read.

### Part 1 — Getting a secure channel

```mermaid
sequenceDiagram
    autonumber
    accTitle: Establishing a secure channel to SQL Server
    accDescr {
        The application resolves the server name through DNS, opens a TCP connection to
        port 1433, exchanges PRELOGIN messages to agree on encryption, and then performs
        a TLS handshake and validates the server certificate.
    }

    participant App as Your app
    participant DNS as DNS
    participant SQL as SQL Server

    Note over App: Read the connection string.<br/>Illegal keyword combinations<br/>fail here, before any network use.

    App->>DNS: Which IP is sql.contoso.com?
    DNS-->>App: 10.0.0.5

    App->>SQL: TCP connect to 10.0.0.5:1433
    SQL-->>App: Accepted

    Note over App,SQL: PRELOGIN: a short "how shall we talk?"<br/>exchange. No credentials yet.
    App->>SQL: PRELOGIN, packet type 0x12<br/>my version, ENCRYPTION = On
    SQL-->>App: PRELOGIN reply<br/>my version, ENCRYPTION = Required

    Note over App,SQL: TLS handshake: switch the channel on.
    App->>SQL: ClientHello
    SQL-->>App: ServerHello and certificate
    Note over App: Check the certificate:<br/>name matches, issuer trusted,<br/>not expired.
    App->>SQL: Finished. Channel is now encrypted.
```

### Part 2 — Proving who you are

The right branch depends entirely on your connection string.

```mermaid
sequenceDiagram
    autonumber
    accTitle: The three SQL Server authentication paths
    accDescr {
        Over the encrypted channel the client authenticates in one of three ways. With a
        user name and password it sends a LOGIN7 packet. With Integrated Security it
        performs an SSPI Kerberos exchange. With Entra authentication the server sends
        FEDAUTHINFO, the client obtains a token from Entra ID, and returns a FEDAUTH
        packet. The server replies with LOGINACK on success or an error token on failure.
    }

    participant App as Your app
    participant SQL as SQL Server
    participant IdP as Microsoft Entra ID

    alt User name and password
        App->>SQL: LOGIN7, packet type 0x10<br/>carries user name and password
    else Integrated Security = true (Kerberos)
        App->>SQL: LOGIN7 plus SSPI blob, packet type 0x11
        SQL-->>App: SSPI challenge
        App->>SQL: SSPI response
    else Authentication = Active Directory ...
        SQL-->>App: FEDAUTHINFO: use this authority,<br/>ask for this resource
        App->>IdP: May I have a token for SQL?
        IdP-->>App: Access token (a JWT)
        App->>SQL: FEDAUTH token, packet type 0x08
    end

    alt Accepted
        SQL-->>App: LOGINACK, then ENVCHANGE<br/>(database, collation, packet size)
        Note over App,SQL: Connection is open. You can run queries.
    else Rejected
        SQL-->>App: ERROR token, for example 18456 "Login failed"
    end
```

---

## Step 1: Read the connection string

Before a single packet is sent, the driver checks what you gave it.

Some combinations are simply illegal. `Authentication=Active Directory Default` together with a
`Password` is rejected outright, because that mode never uses one.

This is the cheapest failure to fix, and it needs no server at all.

## Step 2: Find the server

`Server=sql.contoso.com` is a name. The network needs an address, and DNS supplies it.

Two cases need extra care:

- **Named instances.** `Server=host\SQLEXPRESS` has no fixed port. The driver asks the **SQL
  Browser** service on **UDP port 1434** which port that instance uses. UDP 1434 is blocked on
  many networks, and then this step fails even though everything else is healthy.
- **Azure SQL.** The name resolves to a *gateway*, not to your database. See
  [Azure SQL redirection](#azure-sql-redirection) below.

## Step 3: Connect over TCP

An ordinary TCP connection to port 1433, or to whatever port the Browser reported.

There are three outcomes, and telling them apart matters enormously:

| Outcome | What it means | Typical fix |
| --- | --- | --- |
| Accepted | Something is listening | — |
| **Refused** (TCP RST) | Host reachable, nothing on that port | Start the service, or correct the port |
| **Silence** until timeout | A firewall is *dropping* packets | Open the firewall or network ACL |

Refused and silent produce near-identical error messages, yet the fixes are unrelated. This is one
of the most common sources of wasted debugging time.

## Step 4: Agree on the rules (PRELOGIN)

Now the first TDS message. The client sends a small packet (**type `0x12`**) describing what it
supports, and the server answers in the same shape. No credentials are involved yet.

The field that matters most is **ENCRYPTION**. Each side states a position:

| Value | Byte | Meaning |
| --- | --- | --- |
| `Off` | `0x00` | I would rather not encrypt |
| `On` | `0x01` | I would like to encrypt |
| `NotSupported` | `0x02` | I cannot encrypt |
| `Required` | `0x03` | I insist on encryption |

If the server says `Required` and the client says `NotSupported`, the conversation ends here.

Microsoft.Data.SqlClient 4.0 and later **require encryption by default**. This is why upgrading the
driver can suddenly break a connection that worked unchanged for years.

The server also answers **FEDAUTHREQUIRED**, its way of saying "you will need a cloud token".

## Step 5: Turn on encryption (TLS)

This is ordinary TLS with one twist that surprises everyone who inspects the traffic.

```mermaid
%%{init: {"htmlLabels": false, "flowchart": {"htmlLabels": false}} }%%
flowchart TB
    accTitle: TLS handshake records are wrapped inside TDS packets
    accDescr {
        During the handshake, each TLS record is wrapped inside a TDS packet of type 0x12
        before being sent. After the handshake completes, application data travels as
        ordinary TLS records directly over the socket.
    }

    subgraph during["DURING the handshake"]
        direction LR
        A1["TLS<br/>ClientHello"] --> A2["wrapped inside a<br/>TDS packet, type 0x12"] --> A3["sent to<br/>server"]
    end

    subgraph after["AFTER the handshake"]
        direction LR
        B1["Your SQL<br/>query"] --> B2["ordinary<br/>TLS record"] --> B3["sent to<br/>server"]
    end

    during --> after

    classDef wrapped fill:#fef3c7,stroke:#92400e,stroke-width:1px,color:#111827
    classDef plain fill:#dcfce7,stroke:#166534,stroke-width:1px,color:#111827

    class A1,A2,A3 wrapped
    class B1,B2,B3 plain
```

**During the handshake, TLS records travel inside TDS packets.** Only afterwards do they go
directly over the socket. Hand a raw socket to a TLS library and the server never recognises the
ClientHello: it simply waits, and you get a timeout with no explanation.

Next the client validates the certificate. Most encryption failures live here:

- Does the certificate name match **the name you typed**? Connecting to `10.0.0.5` fails against a
  certificate issued for `sql.contoso.com`. Same machine, different name.
- Is the issuing authority trusted by **this client machine**?
- Has the certificate expired?

`TrustServerCertificate=true` skips every one of those checks. The error disappears, and so does
the protection: traffic is still encrypted, but you no longer know **who** you are encrypted *to*.
Treat it as a temporary diagnostic, never as a fix.

## Step 6: Prove who you are

Three mechanisms, failing for entirely different reasons.

```mermaid
%%{init: {"htmlLabels": false, "flowchart": {"htmlLabels": false}} }%%
flowchart TD
    accTitle: Choosing and completing an authentication method
    accDescr {
        From an encrypted channel the path depends on the connection string. User name and
        password sends a LOGIN7 packet for the server to check. Integrated Security needs a
        Kerberos ticket for the MSSQLSvc service principal name; if none can be obtained the
        connection falls back to NTLM or fails. Active Directory authentication obtains a
        token from Entra ID and sends it as a FEDAUTH packet, which can fail due to
        multi-factor authentication, conditional access, or an expired secret.
    }

    Start(["Encrypted channel<br/>ready"]) --> Q{"Which authentication<br/>does the connection<br/>string ask for?"}

    Q -->|"User ID + Password"| S1["LOGIN7, packet<br/>0x10, carries the<br/>credentials"]
    S1 --> S2["Server checks<br/>the login"]
    S2 --> Done

    Q -->|"Integrated Security=true"| K1["Needs a Kerberos<br/>ticket for<br/>MSSQLSvc/host:port"]
    K1 --> K2{"Ticket available?"}
    K2 -->|"Yes"| K3["SSPI exchange,<br/>packet 0x11"] --> Done
    K2 -->|"No: SPN missing<br/>or wrong"| K4["WARNING: silently<br/>falls back to NTLM,<br/>or fails"] --> Fail

    Q -->|"Authentication=<br/>Active Directory ..."| E1["Server sends<br/>FEDAUTHINFO:<br/>authority + resource"]
    E1 --> E2["Client requests a<br/>token from Entra ID"]
    E2 --> E3{"Token issued?"}
    E3 -->|"No: MFA,<br/>conditional access,<br/>expired secret"| Fail
    E3 -->|"Yes"| E4["Send FEDAUTH<br/>token, packet 0x08"]
    E4 --> E5["Server validates it<br/>and maps it to a<br/>database user"] --> Done

    Done(["SUCCESS: LOGINACK,<br/>you are in"])
    Fail(["FAILURE: login rejected"])

    classDef step fill:#dbeafe,stroke:#1e40af,stroke-width:1px,color:#111827
    classDef decision fill:#e5e7eb,stroke:#374151,stroke-width:1px,color:#111827
    classDef warn fill:#fef3c7,stroke:#92400e,stroke-width:2px,color:#111827
    classDef good fill:#dcfce7,stroke:#166534,stroke-width:2px,color:#111827
    classDef bad fill:#fee2e2,stroke:#991b1b,stroke-width:2px,color:#111827

    class Start,S1,S2,K1,K3,E1,E2,E4,E5 step
    class Q,K2,E3 decision
    class K4 warn
    class Done good
    class Fail bad
```

The distinction that trips up the most people:

| Setting | Authenticates to | Needs an SPN? |
| --- | --- | --- |
| `Integrated Security=true` | **SQL Server**, via Kerberos or NTLM | Yes: `MSSQLSvc/...` |
| `Authentication=Active Directory Integrated` | **Microsoft Entra ID**, via MSAL | No |

The names are nearly identical; the machinery is completely different. Registering SPNs to fix the
second one is a guaranteed dead end.

## Step 7: The session opens

The server sends **LOGINACK**, followed by **ENVCHANGE** tokens carrying the current database,
collation, and negotiated packet size. Only now can you run a query.

---

## Two failures that are not really login

### Azure SQL redirection

```mermaid
%%{init: {"htmlLabels": false, "flowchart": {"htmlLabels": false}} }%%
flowchart LR
    accTitle: Azure SQL redirect connection policy
    accDescr {
        The client first connects to the Azure gateway on port 1433. In Redirect mode the
        gateway replies with the address of the node hosting the database, and the client
        reconnects to that node on a port between 11000 and 11999. A firewall allowing only
        port 1433 blocks this second connection.
    }

    A["Client"] -->|"1. connect on<br/>port 1433"| G["Azure<br/>gateway"]
    G -->|"2. your database is<br/>on this node"| A
    A -->|"3. reconnect on<br/>port 11000-11999"| N["Database<br/>node"]

    classDef step fill:#dbeafe,stroke:#1e40af,stroke-width:1px,color:#111827
    classDef target fill:#dcfce7,stroke:#166534,stroke-width:2px,color:#111827

    class A,G step
    class N target
```

Under the **Redirect** policy the client is told to reconnect on a port in the range
**11000-11999**. A firewall that permits only 1433 lets the first connection through and blocks the
second, so the connection appears to work intermittently, or works from one network but not
another.

Under the **Proxy** policy everything stays on 1433 and the problem disappears, at some cost in
latency.

### Error 18456 hides its own reason

`Login failed for user 'x'` carries a **state** that says *why*: wrong password, disabled account,
locked-out account, missing database, and so on.

For security, SQL Server **reports state 1 to the client regardless of the real state**. The true
value is written only to the **server error log**. So when you see state 1, the answer is on the
server, not in your application.

---

## Where each failure lands

This is exactly how `sqlconn-analyze` is organised: one probe per layer, in flow order, so the
first stage that fails is the actual cause.

```mermaid
%%{init: {"htmlLabels": false, "flowchart": {"htmlLabels": false}} }%%
flowchart LR
    accTitle: The nine analyzer stages in execution order
    accDescr {
        Nine stages run in a fixed order, shown as two columns. The first column is
        connection string, name resolution, TCP reachability, TDS PRELOGIN and TLS
        handshake. The second column continues with routing and redirection, credential
        acquisition, LOGIN7, and resiliency and pooling. The failure each stage detects
        is listed in the table that follows.
    }

    subgraph c1[" "]
        direction TB
        S1["1. Connection string"] --> S2["2. Name resolution"]
        S2 --> S3["3. TCP reachability"]
        S3 --> S4["4. TDS PRELOGIN"]
        S4 --> S5["5. TLS handshake"]
    end
    subgraph c2[" "]
        direction TB
        S6["6. Routing and redirection"] --> S7["7. Credential acquisition"]
        S7 --> S8["8. LOGIN7"]
        S8 --> S9["9. Resiliency and pooling"]
    end
    S5 --> S6

    style c1 fill:none,stroke:none
    style c2 fill:none,stroke:none

    classDef stage fill:#dbeafe,stroke:#1e40af,stroke-width:1px,color:#111827
    class S1,S2,S3,S4,S5,S6,S7,S8,S9 stage
```

Each stage detects a distinct class of failure:

| # | Stage | What a failure here means |
|---|-------|---------------------------|
| 1 | Connection string | Illegal keyword combination |
| 2 | Name resolution | Wrong name, DNS or VPN problem, UDP 1434 blocked |
| 3 | TCP reachability | Service down, wrong port, firewall |
| 4 | TDS PRELOGIN | Encryption cannot be agreed, or not a SQL endpoint |
| 5 | TLS handshake | Certificate name, trust, or expiry |
| 6 | Routing and redirection | Ports 11000-11999 blocked |
| 7 | Credential acquisition | No Kerberos ticket, no Entra token |
| 8 | LOGIN7 | Credentials rejected, or no access to the database |
| 9 | Resiliency and pooling | Pool exhaustion, timeouts |

> **The rule to remember:** a failure at any stage means the later stages never ran. Read the
> *first* failure, not the last error message. The last one is usually just the wreckage.

---

## Glossary

| Term | Meaning |
| --- | --- |
| **TDS** | Tabular Data Stream, the wire protocol SQL Server speaks. Documented as MS-TDS. |
| **PRELOGIN** | The opening TDS message (type `0x12`) where both sides state their capabilities. |
| **LOGIN7** | The TDS message (type `0x10`) that carries login details. |
| **FEDAUTH** | The TDS message (type `0x08`) carrying a Microsoft Entra token. |
| **SSPI** | The Windows interface used for Kerberos and NTLM authentication (packet type `0x11`). |
| **SPN** | Service Principal Name, such as `MSSQLSvc/sql.contoso.com:1433`. Kerberos uses it to identify the service being contacted. |
| **TGT** | Ticket Granting Ticket. The Kerberos ticket used to request all other tickets. |
| **JWT** | JSON Web Token, the format of an Entra access token. |
| **ENVCHANGE** | A TDS token telling the client that some session setting changed. |
| **SQL Browser** | A service on UDP 1434 that reports which port a named instance is listening on. |
