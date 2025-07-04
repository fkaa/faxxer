use std::fs;

use escpos::{
    driver::UsbDriver,
    printer::Printer,
    ui::line::LineBuilder,
    utils::{Font, Protocol, QRCodeCorrectionLevel, QRCodeModel, QRCodeOption},
};
use log::*;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Request, Response, ResponseBox};

fn main() {
    env_logger::init();

    let driver = UsbDriver::open(0x04b8, 0x0e28, None, None).unwrap();
    let mut printer = Printer::new(driver, Protocol::default(), None);

    let server = tiny_http::Server::http("127.0.0.1:8000").unwrap();

    info!("Listening for HTTP requests...");
    for mut req in server.incoming_requests() {
        let response = get_response(&mut req, &mut printer);

        debug!(
            "{} {} => {}",
            req.method(),
            req.url(),
            response.status_code().0
        );

        let _ = req.respond(response);
    }
}

fn get_response(req: &mut Request, printer: &mut Printer<UsbDriver>) -> ResponseBox {
    let url = req.url();

    if let Some((_, path)) = url.split_once("/") {
        debug!("{path:?}");
        match path {
            "editorjs.mjs" | "header.mjs" => {
                let content = fs::read(path).unwrap();
                return Response::from_data(content)
                    .with_header(
                        Header::from_bytes(&b"Content-Type"[..], &b"application/javascript"[..])
                            .unwrap(),
                    )
                    .with_status_code(200)
                    .boxed();
            }
            "" | "index.html" => {
                let content = fs::read("index.html").unwrap();
                return Response::from_data(content).with_status_code(200).boxed();
            }
            "favicon.ico" => {
                return Response::from_data(include_bytes!("../favicon.ico"))
                    .with_status_code(200)
                    .boxed();
            }
            "api/print" => {
                return print_api(req, printer);
            }
            _ => {}
        }
    }

    Response::from_string("Not found")
        .with_status_code(404)
        .boxed()
}

fn print(text: Text, printer: &mut Printer<UsbDriver>) -> anyhow::Result<()> {
    for b in text.blocks {
        match b.block_type.as_str() {
            "header" => write_header(b, printer)?,
            "paragraph" => write_para(b, printer)?,
            _ => {}
        }
    }

    printer.print_cut()?;

    Ok(())
}

fn get_header_size(level: Option<i64>) -> u8 {
    match level {
        Some(i) => match i {
            1 => 5,
            2 => 4,
            3 => 3,
            4 => 2,
            _ => 1,
        },
        None => 1,
    }
}

fn write_header(b: Block, printer: &mut Printer<UsbDriver>) -> anyhow::Result<()> {
    let sz: u8 = get_header_size(b.data.level);
    printer.size(sz, sz)?;
    printer.writeln(&b.data.text)?;

    Ok(())
}

fn write_para(mut b: Block, printer: &mut Printer<UsbDriver>) -> anyhow::Result<()> {
    printer.size(2, 2)?;

    b.data.text = b.data.text.replace("&nbsp;", " ");
    let mut unescaped = String::new();
    html_escape::decode_html_entities_to_string(&b.data.text, &mut unescaped);
    for part in split_urls(&unescaped) {
        match part {
            Part::Text(text) => {
                printer.write(text)?;
            }
            Part::Url(url) => {
                printer.feed()?;

                printer.qrcode_option(
                    url,
                    QRCodeOption::new(QRCodeModel::Model2, 5, QRCodeCorrectionLevel::H),
                )?;

                printer.feed()?;
            }
        }
    }

    printer.feed()?;

    Ok(())
}

enum Part<'a> {
    Text(&'a str),
    Url(&'a str),
}

fn split_urls<'a>(text: &'a str) -> Vec<Part<'a>> {
    let regex = RegexBuilder::new(r"(https?:\/\/(?:www\.|)[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|)[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})")
    .multi_line(true).build().unwrap();

    let mut result = Vec::new();
    let mut last = 0;
    for (index, matched) in text.match_indices(&regex) {
        if last != index {
            result.push(Part::Text(&text[last..index]));
        }
        result.push(Part::Url(matched));
        last = index + matched.len();
    }
    if last < text.len() {
        result.push(Part::Text(&text[last..]));
    }
    result
}

#[derive(Serialize, Deserialize)]
pub struct Text {
    time: i64,
    blocks: Vec<Block>,
    version: String,
}

#[derive(Serialize, Deserialize)]
pub struct Block {
    id: String,
    #[serde(rename = "type")]
    block_type: String,
    data: Data,
}

#[derive(Serialize, Deserialize)]
pub struct Data {
    text: String,
    level: Option<i64>,
}

#[macro_export]
macro_rules! try_unwrap {
    ($obj:expr) => {{
        match $obj {
            Ok(result) => result,
            Err(e) => {
                return Response::from_string(format!("{e:?}"))
                    .with_status_code(400)
                    .boxed();
            }
        }
    }};
}

#[macro_export]
macro_rules! try_json {
    ($req:expr) => {{
        let mut content = String::new();
        if let Err(e) = $req.as_reader().read_to_string(&mut content) {
            return Response::from_string(format!("{e:?}"))
                .with_status_code(400)
                .boxed();
        }

        let result = crate::try_unwrap!(serde_json::from_str(&content));

        result
    }};
}

fn print_api(request: &mut Request, printer: &mut Printer<UsbDriver>) -> ResponseBox {
    let r: Text = crate::try_json!(request);

    match print(r, printer) {
        Ok(()) => return Response::empty(200).boxed(),
        Err(e) => {
            return Response::from_string(format!("{e:?}"))
                .with_status_code(500)
                .boxed();
        }
    }
}
