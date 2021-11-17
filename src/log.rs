use std::{collections::HashMap, fmt};

use ansi_term::{
    Colour::{self, Blue as ColorServer, Red as ColorClient},
    Style,
};
use tracing::{field::Field, span::Attributes, Event, Id, Level, Subscriber};
use tracing_subscriber::{field::Visit, layer::Context, registry::LookupSpan, Layer};

use crate::Protocol;

pub struct TraceLayer {
    pub protocol: Option<Protocol>,
}

impl<S: Subscriber + for<'lookup> LookupSpan<'lookup>> Layer<S> for TraceLayer {
    fn on_new_span(&self, attrs: &Attributes, id: &Id, ctx: Context<S>) {
        if !matches!(attrs.metadata().name(), "session" | "session_test") {
            return;
        }

        let (span, visitor) = {
            let mut visitor = CollectVisitor::new();
            attrs.record(&mut visitor);
            (ctx.span(id).unwrap(), visitor)
        };

        match attrs.metadata().name() {
            "session" => {
                span.extensions_mut().insert(Session {
                    sid: visitor.get("sid").unwrap().into(),
                });
            }
            "session_test" => {
                span.extensions_mut().insert(SessionTest {
                    sid: visitor.get("sid").unwrap().into(),
                    protocol: visitor.get("protocol").unwrap().into(),
                    testcase: visitor.get("testcase").unwrap().into(),
                    application: visitor.get("application").unwrap().into(),
                });
            }
            _ => unreachable!(),
        }
    }

    fn on_event(&self, event: &Event, ctx: Context<S>) {
        let eventv = {
            let mut event_visitor = CollectVisitor::new();
            event.record(&mut event_visitor);
            event_visitor
        };

        if let Some(target_proto) = self.protocol {
            if let Some(span) = ctx.lookup_current() {
                let extn = span.extensions();
                if let Some(session_test) = extn.get::<SessionTest>() {
                    if session_test.protocol.to_lowercase()
                        != target_proto.to_string().to_lowercase()
                    {
                        return;
                    }
                } else {
                    return;
                }
            } else {
                return;
            }
        }

        if *event.metadata().level() == Level::ERROR {
            if let Some(span) = ctx.lookup_current() {
                if let Some(session) = span.extensions().get::<Session>() {
                    let color = Colour::Fixed(session.sid.chars().next().unwrap() as u8);

                    print!("{} | ", Style::default().on(color).paint(&session.sid));
                }
                if let Some(session_test) = span.extensions().get::<SessionTest>() {
                    print!(
                        "{} ({}) > {} | ",
                        session_test.testcase, session_test.application, session_test.sid
                    );
                }
            }
            println!("{:?}", eventv.map);
        }

        if !matches!(
            eventv.get("message").unwrap(),
            "send" | "read" | "accept tls" | "accept compression"
        ) {
            return;
        }

        let span = ctx.lookup_current().unwrap();
        let extn = span.extensions();

        let prefix = {
            match span.metadata().name() {
                "session" => {
                    let session = extn.get::<Session>().unwrap();
                    format!("{}", session.sid)
                }
                "session_test" => {
                    let session_test = extn.get::<SessionTest>().unwrap();
                    format!(
                        "{} ({}) > {}",
                        session_test.testcase, session_test.application, session_test.sid
                    )
                }
                _ => unreachable!(),
            }
        };

        let bg_color = Colour::Fixed(prefix.chars().next().unwrap() as u8);

        if eventv.get("message").unwrap() == "accept compression" {
            println!(
                "{} | <----- Compression ----->",
                Style::default().on(bg_color).paint(&prefix)
            );
        } else if eventv.get("message").unwrap() == "accept tls" {
            println!(
                "{} | <----- TLS handshake ----->",
                Style::default().on(bg_color).paint(&prefix)
            );
        } else {
            let (sym, color) = match (eventv.get("message").unwrap(), eventv.get("tls").unwrap()) {
                ("send", "false") => ("S:", ColorServer.normal()),
                ("send", "true") => ("S:", ColorServer.bold()),
                ("read", "false") => ("C:", ColorClient.normal()),
                ("read", "true") => ("C:", ColorClient.bold()),
                _ => unreachable!(),
            };

            let lines = eventv.get("msg").unwrap().lines().collect::<Vec<_>>();

            if let Some((first, rest)) = lines.split_first() {
                println!(
                    "{} | {} {}",
                    Style::default().on(bg_color).paint(&prefix),
                    sym,
                    color.paint(*first)
                );

                for line in rest.iter() {
                    println!(
                        "{} | {} {}",
                        Style::default().on(bg_color).paint(&prefix),
                        "..",
                        color.paint(*line)
                    );
                }
            }
        }
    }
}

#[derive(Debug)]
struct Session {
    pub sid: String,
}

#[derive(Debug)]
struct SessionTest {
    pub sid: String,
    pub protocol: String,
    pub testcase: String,
    pub application: String,
}

#[derive(Debug)]
struct CollectVisitor {
    map: HashMap<&'static str, String>,
}

impl CollectVisitor {
    pub fn new() -> CollectVisitor {
        CollectVisitor {
            map: HashMap::default(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.map.get(key).map(|s| s.as_str())
    }
}

impl Visit for CollectVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.map.insert(field.name(), format!("{:?}", value));
    }
}
