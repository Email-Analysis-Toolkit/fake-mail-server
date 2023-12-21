use std::{io, path::PathBuf, process::Command};

use anyhow::Context;
use fake_mail_server::{
    error::StringError,
    filter::Filter,
    imap::{account::Account, config::Config as ImapConfig, ImapServer},
    log::TraceLayer,
    parse_protocol,
    pop3::{config::Config as Pop3Config, Pop3Server},
    smtp::{config::Config as SmtpConfig, SmtpServer},
    utils::sample_sid,
    ConsolidatedStream, Protocol, Splitter,
};
use structopt::StructOpt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, info_span, Instrument};
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, FmtSubscriber};

use crate::config::{read_ron_config, Config};

mod config;

async fn spawn_benign_smtp(main_config: Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&main_config.smtp)
        .await
        .context(format!("Failed to bind to {}", &main_config.smtp))?;

    let test_config: SmtpConfig = {
        let path = if main_config.setup_opportunistic_encryption {
            "testcases/smtp/setup_opportunistic_encryption.ron"
        } else {
            "testcases/smtp/setup.ron"
        };
        read_ron_config(path).context(format!("Could not load SMTP config at path \"{}\"", path))?
    };

    loop {
        let span = info_span!(
            "session",
            sid=%sample_sid(),
        );

        let socket = accept_new_connection(&listener, &main_config.filter)
            .instrument(span.clone())
            .await?;
        let test_config = test_config.clone();

        tokio::spawn(
            SmtpServer::new(ConsolidatedStream::new(Box::new(socket)), test_config)
                .run()
                .instrument(span),
        );
    }
}

async fn spawn_benign_pop3(main_config: Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&main_config.pop3)
        .await
        .context(format!("Failed to bind to {}", &main_config.pop3))?;

    let test_config: Pop3Config = {
        let path = if main_config.setup_opportunistic_encryption {
            "testcases/pop3/setup_opportunistic_encryption.ron"
        } else {
            "testcases/pop3/setup.ron"
        };
        read_ron_config(path).context(format!("Could not load POP3 config at path \"{}\"", path))?
    };

    loop {
        let span = info_span!(
            "session",
            sid=%sample_sid(),
        );

        let socket = accept_new_connection(&listener, &main_config.filter)
            .instrument(span.clone())
            .await?;
        let test_config = test_config.clone();

        tokio::spawn(
            Pop3Server::new(ConsolidatedStream::new(Box::new(socket)), test_config)
                .run()
                .instrument(span),
        );
    }
}

async fn spawn_benign_imap(main_config: Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&main_config.imap)
        .await
        .context(format!("Failed to bind to {}", &main_config.imap))?;

    let test_config: ImapConfig = {
        let path = if main_config.setup_opportunistic_encryption {
            "testcases/imap/setup_opportunistic_encryption.ron"
        } else {
            "testcases/imap/setup.ron"
        };
        read_ron_config(path).context(format!("Could not load IMAP config at path \"{}\"", path))?
    };

    let account = {
        let path = "mails";
        Account::from_dir(path, &test_config.folders).context(format!(
            "Failed to create mailbox from \"{}\" directory",
            path
        ))?
    };

    loop {
        let span = info_span!(
            "session",
            sid=%sample_sid(),
        );

        let socket = accept_new_connection(&listener, &main_config.filter)
            .instrument(span.clone())
            .await?;
        let test_config = test_config.clone();

        let account = account.clone();

        tokio::spawn(
            ImapServer::new(
                ConsolidatedStream::new(Box::new(socket)),
                account,
                test_config,
            )
            .run()
            .instrument(span),
        );
    }
}

async fn spawn_looping_smtp(
    main_config: Config,
    testcase: String,
    protocol: Protocol,
    application: String,
) -> anyhow::Result<()> {
    let span = info_span!("session_test", %protocol, ?application,
                testcase=%testcase, sid=%sample_sid());
    let listener = TcpListener::bind(&main_config.smtp)
        .await
        .context(format!("Failed to bind to {}", &main_config.smtp))?;

    let test_config: SmtpConfig = {
        let path = testcase.as_str();
        read_ron_config(path).context(format!("Could not load SMTP config at path \"{}\"", path))?
    };

    loop {
        let new_span = span.clone();
        let socket = accept_new_connection(&listener, &main_config.filter).await?;
        let test_config = test_config.clone();

        tokio::spawn(async move {
            SmtpServer::new(ConsolidatedStream::new(Box::new(socket)), test_config)
                .run()
                .instrument(new_span)
                .await;
        });
    }
}

async fn spawn_looping_pop3(
    main_config: Config,
    testcase: String,
    protocol: Protocol,
    application: String,
) -> anyhow::Result<()> {
    let span = info_span!("session_test", %protocol, ?application,
                testcase=%testcase, sid=%sample_sid());
    let listener = TcpListener::bind(&main_config.pop3)
        .await
        .context(format!("Failed to bind to {}", &main_config.pop3))?;

    let test_config: Pop3Config = {
        let path = testcase.as_str();
        read_ron_config(path).context(format!("Could not load POP3 config at path \"{}\"", path))?
    };

    loop {
        let new_span = span.clone();
        let socket = accept_new_connection(&listener, &main_config.filter).await?;
        let test_config = test_config.clone();

        tokio::spawn(async move {
            Pop3Server::new(ConsolidatedStream::new(Box::new(socket)), test_config)
                .run()
                .instrument(new_span)
                .await;
        });
    }
}

async fn spawn_looping_imap(
    main_config: Config,
    testcase: String,
    protocol: Protocol,
    application: String,
) -> anyhow::Result<()> {
    let span = info_span!("session_test", %protocol, ?application,
                testcase=%testcase, sid=%sample_sid());
    let listener = TcpListener::bind(&main_config.imap)
        .await
        .context(format!("Failed to bind to {}", &main_config.imap))?;

    let test_config: ImapConfig = {
        let path = testcase.as_str();
        read_ron_config(path).context(format!("Could not load IMAP config at path \"{}\"", path))?
    };

    let account = {
        let path = "mails";
        Account::from_dir(path, &test_config.folders).context(format!(
            "Failed to create mailbox from \"{}\" directory",
            path
        ))?
    };

    loop {
        let new_span = span.clone();
        let socket = accept_new_connection(&listener, &main_config.filter).await?;
        let test_config = test_config.clone();
        let account = account.clone();

        tokio::spawn(async move {
            ImapServer::new(
                ConsolidatedStream::new(Box::new(socket)),
                account,
                test_config,
            )
            .run()
            .instrument(new_span)
            .await;
        });
    }
}

async fn accept_new_connection(listener: &TcpListener, filter: &Filter) -> io::Result<TcpStream> {
    loop {
        let (stream, addr) = listener.accept().await?;

        if filter.accepts(&addr.to_string()) {
            let local_addr = stream.local_addr().unwrap();
            let peer_addr = stream.peer_addr().unwrap();

            info!(%local_addr, %peer_addr, "accept");
            break Ok(stream);
        } else {
            println!("blocked {}", addr);
        }
    }
}

fn reset_sut(config: &Config, application: &str, protocol: Protocol) -> anyhow::Result<()> {
    if let Some(ref script) = config.script {
        let output = Command::new(script)
            .arg(application)
            .arg(protocol.to_string())
            .output()
            .context(format!("Failed to execute script \"{}\"", script))?;

        let msg = String::from_utf8(output.stdout)
            .context("Output of reset script must be valid UTF-8")?;

        for line in msg.lines() {
            println!("{} | {}", script, line);
        }

        if !output.status.success() {
            return Err(StringError::new(format!("Script failed with {}", output.status)).into());
        }
    }

    Ok(())
}

fn wait_enter() -> io::Result<()> {
    let mut line = String::new();
    println!("<Press ENTER to continue>");

    std::io::stdin().read_line(&mut line)?;
    println!("\n\n\n\n\n");

    Ok(())
}

/// Fake Mail Server
#[derive(Debug, StructOpt)]
enum Args {
    /// Use this command for initial configuration of an email client
    Setup {
        /// Global config file
        #[structopt(long, short, default_value = "config.ron")]
        config: String,
    },
    /// Use this command to execute specific tests against an email client
    Test {
        /// Name of the application under test
        application: String,
        /// Protocol to test (`smtp`, `pop3`, or `imap`)
        #[structopt(parse(try_from_str = parse_protocol))]
        protocol: Protocol,
        /// Configuration files for testcase
        #[structopt(parse(from_os_str), required = true)]
        testcases: Vec<PathBuf>,
        /// Global config file to specify ports, filters, ...
        #[structopt(long, short, default_value = "config.ron")]
        config: String,
    },

    /// Use this command to execute a specific testcase in a loop against an email client
    LoopTest {
        /// Name of the application under test
        application: String,
        /// Protocol to test (`smtp`, `pop3`, or `imap`)
        #[structopt(parse(try_from_str = parse_protocol))]
        protocol: Protocol,
        /// Configuration file for testcase
        #[structopt(parse(from_os_str), required = true)]
        testcase: PathBuf,
        /// Global config file to specify ports, filters, ...
        #[structopt(long, short, default_value = "config.ron")]
        config: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::from_args();

    // ---------------------------------------------------------------

    // Note: _guard must not be dropped.
    let appender = tracing_appender::rolling::daily("logs", "log.json");
    let (appender, _guard) = tracing_appender::non_blocking(appender);

    let subscriber = {
        let filter_layer =
            EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("trace"))?;

        FmtSubscriber::builder()
            .with_env_filter(filter_layer)
            .with_writer(appender)
            .json()
            .finish()
            .with(TraceLayer {
                protocol: match args {
                    Args::Setup { .. } => None,
                    Args::Test { protocol, .. } => Some(protocol),
                    Args::LoopTest { protocol, .. } => Some(protocol),
                },
            })
    };

    tracing::subscriber::set_global_default(subscriber)?;

    // ---------------------------------------------------------------

    let main_config: Config = match args {
        Args::Setup { ref config }
        | Args::Test { ref config, .. }
        | Args::LoopTest { ref config, .. } => read_ron_config(config)
            .context(format!("Could not load main config at path \"{}\"", config))?,
    };

    println!("Server starting with ...");
    println!("{:#?}", main_config);
    println!();
    println!("-------------------------------------");
    println!();

    match args {
        Args::Setup { .. } => {
            tokio::try_join!(
                async {
                    spawn_benign_smtp(main_config.clone())
                        .await
                        .context("SMTP component failed")
                },
                async {
                    spawn_benign_pop3(main_config.clone())
                        .await
                        .context("POP3 component failed")
                },
                async {
                    spawn_benign_imap(main_config.clone())
                        .await
                        .context("IMAP component failed")
                },
            )
            .context("Failed to start mail server")?;
        }
        Args::Test {
            protocol,
            testcases,
            application,
            ..
        } => {
            info!(?application, %protocol, "fake_mail_server_start");

            match protocol {
                Protocol::Smtp => {
                    let _pop3 = tokio::spawn(spawn_benign_pop3(main_config.clone()));
                    let _imap = tokio::spawn(spawn_benign_imap(main_config.clone()));

                    for path in testcases.into_iter() {
                        let listener = TcpListener::bind(&main_config.smtp)
                            .await
                            .context(format!("Failed to bind to {}", &main_config.smtp))?;
                        reset_sut(&main_config, &application, protocol)?;

                        let config: SmtpConfig = read_ron_config(&path).context(format!(
                            "Could not load testcase at path \"{}\"",
                            path.display()
                        ))?;

                        let span = info_span!("session_test", %protocol, ?application, testcase=%path.display(), sid=%sample_sid());

                        let stream = accept_new_connection(&listener, &main_config.filter).await?;

                        let task_result = tokio::spawn(
                            SmtpServer::new(ConsolidatedStream::new(Box::new(stream)), config)
                                .run()
                                .instrument(span),
                        )
                        .await;

                        if let Err(task_result) = task_result {
                            error!(?task_result, "spawn result");
                        }

                        drop(listener);
                        wait_enter()?;
                    }
                }
                Protocol::Pop3 => {
                    let _smtp = tokio::spawn(spawn_benign_smtp(main_config.clone()));
                    let _imap = tokio::spawn(spawn_benign_imap(main_config.clone()));

                    for path in testcases.into_iter() {
                        let listener = TcpListener::bind(&main_config.pop3)
                            .await
                            .context(format!("Failed to bind to {}", &main_config.pop3))?;

                        reset_sut(&main_config, &application, protocol)?;

                        let config: Pop3Config = read_ron_config(&path).context(format!(
                            "Could not load testcase at path \"{}\"",
                            path.display()
                        ))?;

                        let span = info_span!("session_test", %protocol, ?application, testcase=%path.display(), sid=%sample_sid());

                        let stream = accept_new_connection(&listener, &main_config.filter).await?;

                        let task_result = tokio::spawn(
                            Pop3Server::new(ConsolidatedStream::new(Box::new(stream)), config)
                                .run()
                                .instrument(span),
                        )
                        .await;

                        if let Err(task_result) = task_result {
                            error!(?task_result, "spawn result");
                        }

                        drop(listener);
                        wait_enter()?;
                    }
                }
                Protocol::Imap => {
                    let _smtp = tokio::spawn(spawn_benign_smtp(main_config.clone()));
                    let _pop3 = tokio::spawn(spawn_benign_pop3(main_config.clone()));

                    for path in testcases.into_iter() {
                        let listener = TcpListener::bind(&main_config.imap)
                            .await
                            .context(format!("Failed to bind to {}", &main_config.imap))?;

                        reset_sut(&main_config, &application, protocol)?;

                        let config: ImapConfig = read_ron_config(&path).context(format!(
                            "Could not load testcase at path \"{}\"",
                            path.display()
                        ))?;

                        let account = Account::from_dir("mails", &config.folders).context(
                            format!("Failed to create mailbox from \"{}\" directory", "mails"),
                        )?;

                        let span = info_span!("session_test", %protocol, ?application, testcase=%path.display(), sid=%sample_sid());

                        let stream = accept_new_connection(&listener, &main_config.filter).await?;

                        let task_result = tokio::spawn(
                            ImapServer::new(
                                ConsolidatedStream::new(Box::new(stream)),
                                account.clone(),
                                config.clone(),
                            )
                            .run()
                            .instrument(span),
                        )
                        .await;

                        if let Err(task_result) = task_result {
                            error!(?task_result, "spawn result");
                        }

                        // ---------------------------------------------------------------------------------

                        // FIXME: Do not listen for second connection for now ...

                        /*
                        let result = timeout(
                            Duration::from_secs(5),
                            accept_new_connection(&listener, &main_config.filter),
                        )
                        .await?;
                        match result {
                            Ok(stream) => {
                                let span = info_span!("session_test", %protocol, ?application, testcase=%path.display(), sid=%sample_sid());
                                let task_result = tokio::spawn(
                                    ImapServer::new(
                                        ConsolidatedStream::Plain(stream),
                                        account,
                                        config,
                                    )
                                    .run()
                                    .instrument(span),
                                )
                                .await;
                                if let Err(task_result) = task_result {
                                    error!(?task_result, "spawn result");
                                }
                            }
                            Err(panic) => {
                                println!("Server panicked... {:?}", panic);
                            }
                        }
                        */

                        drop(listener);
                        wait_enter()?;
                    }
                }
            }
        }

        Args::LoopTest {
            protocol,
            testcase,
            application,
            ..
        } => {
            info!(?application, %protocol, "fake_mail_server_start");
            let path = testcase.to_str().unwrap().to_owned();
            match protocol {
                Protocol::Smtp => {
                    tokio::try_join!(
                        async {
                            spawn_looping_smtp(main_config.clone(), path, protocol, application)
                                .await
                                .context("SMTP component failed")
                        },
                        async {
                            spawn_benign_pop3(main_config.clone())
                                .await
                                .context("POP3 component failed")
                        },
                        async {
                            spawn_benign_imap(main_config.clone())
                                .await
                                .context("IMAP component failed")
                        },
                    )
                    .context("Failed to start mail server")?;
                }
                Protocol::Pop3 => {
                    tokio::try_join!(
                        async {
                            spawn_benign_smtp(main_config.clone())
                                .await
                                .context("SMTP component failed")
                        },
                        async {
                            spawn_looping_pop3(main_config.clone(), path, protocol, application)
                                .await
                                .context("POP3 component failed")
                        },
                        async {
                            spawn_benign_imap(main_config.clone())
                                .await
                                .context("IMAP component failed")
                        },
                    )
                    .context("Failed to start mail server")?;
                }
                Protocol::Imap => {
                    tokio::try_join!(
                        async {
                            spawn_benign_smtp(main_config.clone())
                                .await
                                .context("SMTP component failed")
                        },
                        async {
                            spawn_benign_pop3(main_config.clone())
                                .await
                                .context("POP3 component failed")
                        },
                        async {
                            spawn_looping_imap(main_config.clone(), path, protocol, application)
                                .await
                                .context("IMAP component failed")
                        },
                    )
                    .context("Failed to start mail server")?;
                }
            }
        }
    }

    Ok(())
}
