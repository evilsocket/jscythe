use crate::Error;

pub(crate) mod requests {
    use lazy_static::lazy_static;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    lazy_static! {
        static ref REQUEST_ID: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    }

    #[derive(Serialize)]
    #[serde(untagged)]
    pub(crate) enum ParamValue {
        String(String),
        Bool(bool),
    }

    #[derive(Serialize)]
    pub(crate) struct MethodCall {
        pub id: usize,
        pub method: String,
        pub params: HashMap<String, ParamValue>,
    }

    impl MethodCall {
        pub fn new(method: String, params: HashMap<String, ParamValue>) -> Self {
            let id = REQUEST_ID.fetch_add(1, Ordering::SeqCst);
            Self { id, method, params }
        }
    }

    #[derive(Serialize)]
    pub(crate) struct RuntimeEval(MethodCall);

    impl RuntimeEval {
        pub fn new(expression: &str) -> Self {
            let params = HashMap::from([
                ("awaitPromise".to_owned(), ParamValue::Bool(true)),
                ("includeCommandLineAPI".to_owned(), ParamValue::Bool(true)),
                (
                    "allowUnsafeEvalBlockedByCSP".to_owned(),
                    ParamValue::Bool(true),
                ),
                (
                    "expression".to_owned(),
                    ParamValue::String(expression.to_owned()),
                ),
            ]);
            Self(MethodCall::new("Runtime.evaluate".to_owned(), params))
        }
    }
}

pub(crate) mod responses {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub(crate) struct DebugManifest {
        #[serde(rename(deserialize = "webSocketDebuggerUrl"))]
        pub ws_debugger_url: String,
    }

    #[derive(Deserialize, Debug)]
    pub(crate) struct DomainCommandParam {
        pub name: String,
    }

    #[derive(Deserialize, Debug)]
    pub(crate) struct DomainCommand {
        pub name: String,
        pub parameters: Option<Vec<DomainCommandParam>>,
    }

    impl DomainCommand {
        pub fn display(&self) -> String {
            let args = match &self.parameters {
                Some(params) => params
                    .iter()
                    .map(|p| p.name.to_owned())
                    .collect::<Vec<String>>()
                    .join(", "),
                None => "".to_owned(),
            };
            format!(".{}({})", self.name, args)
        }
    }

    #[derive(Deserialize, Debug)]
    pub(crate) struct Domain {
        pub domain: String,
        pub commands: Vec<DomainCommand>,
    }

    #[derive(Deserialize)]
    pub(crate) struct Protocol {
        pub domains: Vec<Domain>,
    }
}

pub(crate) fn get_domains(port: u16) -> Result<Vec<responses::Domain>, Error> {
    let json_url = format!("http://127.0.0.1:{}/json/protocol", port);
    println!(
        "inspection enabled on port {}, requesting available domains from {} ...",
        port, &json_url
    );

    let body = reqwest::blocking::get(json_url).unwrap().bytes().unwrap();
    let proto: responses::Protocol = serde_json::from_slice(&body).map_err(|e| {
        format!(
            "could not parse protocol definitiont: {:?}\n\nDATA:\n  {:?}",
            e, &body
        )
    })?;

    Ok(proto.domains)
}

pub(crate) fn get_debug_url(port: u16) -> Result<String, Error> {
    let json_url = format!("http://127.0.0.1:{}/json", port);

    println!(
        "inspection enabled on port {}, requesting webSocketDebuggerUrl from {} ...",
        port, &json_url
    );

    let body = reqwest::blocking::get(json_url).unwrap().bytes().unwrap();
    let debug_manifests: Vec<responses::DebugManifest> =
        serde_json::from_slice(&body).map_err(|e| {
            format!(
                "could not parse debug manifest: {:?}\n\nDATA:\n  {:?}",
                e, &body
            )
        })?;

    if debug_manifests.is_empty() {
        return Err("no debug manifests found".to_owned());
    }

    Ok(debug_manifests[0].ws_debugger_url.to_owned())
}
