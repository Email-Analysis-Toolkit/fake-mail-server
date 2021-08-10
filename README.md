![CI](https://github.com/Email-Analysis-Toolkit/fake-mail-server/actions/workflows/ci.yml/badge.svg)
![Scheduled](https://github.com/Email-Analysis-Toolkit/fake-mail-server/actions/workflows/scheduled.yml/badge.svg)

# Fake Mail Server

## 1) Overview

The provided server acts like a normal email server with the difference that it can be configured to answer any command with any response. The exact behavior is configured with test case configurations. Some configurations are in the `testcases` directory. The main configuration `config.ron` contains parameters that are likely to stay the same for a full testing session.

In contrast to server testing, client testing is more difficult. A server testing tool can connect to an always-open port. In client testing, our test server needs to wait for an incoming client connection. Thus, we need to set up an environment where our test server can "request" a connection from any client. We used VM snapshots with pre-configured clients to solve this problem, which are ready to connect to our email server upon a simple event such as a button click. (See the RELEASE page for further instructions.)

## 2) Setup

The server prints a (reduced) human-readable trace in the console and logs all events in a structured format in the `logs` directory.

### 2.1) Build the Server

You can compile the server or use the pre-compiled binary. In both cases, you need OpenSSL development packages (e.g. `libssl-dev` in Ubuntu)

In order to compile the server, you need a working Rust environment. See https://rustup.rs/. Then, execute

```sh
$ cargo build
$ cp ./target/debug/fake_mail_server .
```

### 2.2) Run the Server

Please run the (pre-)compiled binary as root.

```sh
$ sudo ./fake_mail_server
```

Note: Sudo is not required when the binary is given the ability to run on privileged ports (e.g. via `setcap`) and the current user has the right to reset running VMs.

### 2.3) Creation of Keys and Certificates

You can use [mkcert](https://github.com/FiloSottile/mkcert) to setup a local root-CA ...

```sh
$ mkcert -install
```

... and create new X.509 TLS certificates.

The `fake_mail_server` uses the pkcs12 format for now, thus the command to create a locally-valid certificate for `example.org` is ...

```sh
$ mkcert -pkcs12 example.org
```

Note: The default password used by mkcert is `changeit`.

## 3) Setup a MUA for Testing

The server mimics a real email server such that no extra servers (e.g. Postfix + Dovecot) must be installed for testing.

If you want to setup a MUA, execute the `setup` subcommand of the `fake_mail_server` ...

```sh
$ sudo ./fake_mail_server setup
```

... and try to configure a new email account in any MUA of your choice. 

## 4) Test a MUA

In order to execute a test case, use the `test` subcommand. For example, to execute all STARTTLS-stripping tests against IMAP run ...

```sh
$ sudo ./fake_mail_server test <MUA> imap testcases/imap/Negotiation/O_*.ron
```

It should be easy to see if a plaintext login was conducted or not by examining the human-readable trace.

### Interpreting the Server Output

The server output  of the `O_1` IMAP test will look like this:

```
testcases/imap/Negotiation/O_1.ron ("thunderbird") > pzKfOLCA | S: * OK [CAPABILITY IMAP4REV1 AUTH=PLAIN AUTH=LOGIN] IMAP server ready.\r\n
testcases/imap/Negotiation/O_1.ron ("thunderbird") > pzKfOLCA | C: 1 STARTTLS\r\n
testcases/imap/Negotiation/O_1.ron ("thunderbird") > pzKfOLCA | S: 1 BAD STARTTLS not supported.\r\n
testcases/imap/Negotiation/O_1.ron ("thunderbird") > pzKfOLCA | {"message": "Connection was closed."}
```

Every line starts with the test case and application, followed by a unique ID (`pzKfOLCA`) for the test run. The actual messages start after the `|`. Lines starting with `S:` are messages sent by the server and lines starting with `C:` are messages sent by the client. If a line starts with `..`, it continues the last line (as read by a single call to a socket read function). Lines without a special Identifier in front of them are general (error) messages. In this case the client reacted by closing the connection after receiving a `BAD` response to STARTTLS.

## 5) Try Out Existing Test Cases

You can find the test cases used for the "Why TLS is better without STARTTLS: A Security Analysis of STARTTLS in the Email Context" paper in the `testcases` folder. The structure is as follows (comments are related to test results as shown in Table 5 in the paper):

```
testcases
├── imap
│   ├── Buffering    # B_R tests. These require manual testing. Instructions are available in the corresponding ron file.
│   ├── Negotiation  # N_* tests
│   ├── others       # Testcases for specific clients/issues that did not make it into the paper.
│   ├── setup.ron    # Config file for the server setup.
│   ├── Tampering    # T_* tests
│   └── UI Spoofing  # U tests
├── pop3
│   ├── Buffering
│   ├── Negotiation
│   ├── others
│   ├── setup.ron
│   └── Tampering
└── smtp
    ├── Buffering
    ├── Negotiation
    ├── others
    ├── setup.ron
    └── Tampering
```

### 6) Create Additional Test Cases

We suggest you copy an existing testcase and change specific values to create a new one. For many test cases code changes are unnecessary.

#### Example

Let's say you want to create a new IMAP negotiation test case for testing STARTTLS stripping. You would first copy an existing Negotiation test case:

```sh
$ cp testcases/imap/Negotiation/O_3.ron testcases/imap/Negotiation/O_new.ron
```

The existing test case looks as follows (with added comments):

```rust
(
    // Internal IMAP state to start the server in (NotAuthenticated / Authenticated / Selected(Mailbox) / Logout) 
    state: NotAuthenticated,
    // Greeting to send to the client upon a new connection (Ok, No, Bad, Bye, PreAuth)
    // This greeting will result in the message
    // * OK [CAPABILITY IMAP4REV1 STARTTLS AUTH=PLAIN AUTH=LOGIN] IMAP server ready
    greeting: Ok(
        // IMAP tag to use. None means *
        tag: None,
        // IMAP code to send with the greeting. Usually Capabilities as shown here
        code: Some(Capability([Imap4Rev1, StartTls, Auth(Plain), Auth(Login)])),
        // Human readable text to append to the greeting
        text: Text("IMAP server ready.")
    ),
    // IMAP capabilities to send in the NotAuthenticated unencrypted state
    caps: [Imap4Rev1, StartTls, Auth(Plain), Auth(Login)],
    // IMAP capabilities to send in the NotAuthenticated encrypted state
    caps_tls: [Imap4Rev1, Auth(Plain), Auth(Login)],
    // IMAP capabilities to send in the Authenticated unencrypted state
    caps_auth: [Imap4Rev1],
    // IMAP capabilities to send in the Authenticated encrypted state
    caps_tls_auth: [Imap4Rev1],

    // Response to the STARTTLS command. <tag> is a placeholder that will be replaced by the the tag of the STARTTLS command.
    starttls_response: Some("<tag> BAD do not begin TLS now.\r\n"),
    // Should the server transition to TLS after the STARTTLS command?
    starttls_transition: false,

    // Path and password of the server certificate for STARTTLS transitions
    pkcs12: (
        file: "certs/example.org.p12",
        password: "changeit",
    ),
    // Should the server use implicit TLS or STARTTLS?
    implicit_tls: false,
)
```

You can your new testcase as needed (e.g., change the STARTTLS response to `Some("<tag> NOTANIMAPCODE no STARTTLS here.\r\n")`) and run the test with

```sh
$ sudo ./fake_mail_server test thunderbird imap testcases/imap/Negotiation/O_new.ron
```

# License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
