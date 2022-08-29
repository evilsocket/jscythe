use serde::{Deserialize, Serialize};

use crate::Error;

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

#[derive(Serialize)]
pub(crate) struct EvalParams {
    #[serde(rename(serialize = "awaitPromise"))]
    pub await_promise: bool,
    #[serde(rename(serialize = "includeCommandLineAPI"))]
    pub include_commandline_api: bool,
    #[serde(rename(serialize = "allowUnsafeEvalBlockedByCSP"))]
    pub unsafe_eval: bool,
    pub expression: String,
}

#[derive(Serialize)]
pub(crate) struct EvalRequest {
    pub id: usize,
    pub method: String,
    pub params: EvalParams,
}

impl EvalRequest {
    pub fn new(expression: &str) -> Self {
        Self {
            id: 0,
            method: "Runtime.evaluate".to_owned(),
            params: EvalParams {
                await_promise: true,
                include_commandline_api: true,
                unsafe_eval: true,
                expression: expression.to_owned(),
            },
        }
    }
}

pub(crate) fn get_domains(port: u16) -> Result<Vec<Domain>, Error> {
    let json_url = format!("http://127.0.0.1:{}/json/protocol", port);
    println!(
        "inspection enabled on port {}, requesting available domains from {} ...",
        port, &json_url
    );

    let body = reqwest::blocking::get(json_url).unwrap().bytes().unwrap();
    let proto: Protocol = serde_json::from_slice(&body).map_err(|e| {
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
    let debug_manifests: Vec<DebugManifest> = serde_json::from_slice(&body).map_err(|e| {
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
