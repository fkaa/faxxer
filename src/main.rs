use std::{env, fs};

use cookie::{Cookie, CookieBuilder};
use dotenv::dotenv;
use escpos::{
    driver::UsbDriver,
    printer::Printer,
    ui::line::{LineBuilder, LineStyle},
    utils::{Font, JustifyMode, Protocol, QRCodeCorrectionLevel, QRCodeModel, QRCodeOption},
};
use html_parser::Dom;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation};
use log::*;
use rand::{Rng, distr::Alphanumeric};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use serenity::{
    all::{CurrentUser, Http},
    futures,
};
use tiny_http::{Header, Request, Response, ResponseBox};

mod db;

use db::*;

fn main() {
    let _ = dotenv();
    env_logger::init();

    let discord_client_id = env::var("DISCORD_CLIENT_ID").expect("Expected 'DISCORD_CLIENT_ID'");
    let discord_client_secret =
        env::var("DISCORD_CLIENT_SECRET").expect("Expected 'DISCORD_CLIENT_SECRET'");
    let jwt_key = env::var("JWT_KEY").expect("Expected 'JWT_KEY'");
    let jwt_decode_key = DecodingKey::from_base64_secret(&jwt_key).unwrap();

    let jwt_encode_key = EncodingKey::from_base64_secret(&jwt_key).unwrap();
    let redirect_uri = env::var("REDIRECT_URI").expect("Expected 'REDIRECT_URI'");
    let discord_auth_uri = env::var("DISCORD_AUTH_URL").expect("Expected 'DISCORD_AUTH_URL'");
    let user_database_path = env::var("DB_PATH").expect("Expected 'DB_PATH'");

    let discord_bot_client = Http::new(&discord_client_secret);
    let db = Database::open(user_database_path);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();

    let app = App {
        discord_client_id,
        discord_client_secret,
        discord_bot_client,
        jwt_decode_key,
        jwt_encode_key,
        redirect_uri,
        discord_auth_uri,
        rt,
        db,
    };

    let driver = UsbDriver::open(0x04b8, 0x0e28, None, None).unwrap();
    let mut printer = Printer::new(driver, Protocol::default(), None);

    let server = tiny_http::Server::http("127.0.0.1:8002").unwrap();

    info!("Listening for HTTP requests...");
    for mut req in server.incoming_requests() {
        let response = get_response(&mut req, &mut printer, &app);

        debug!(
            "{} {} => {}",
            req.method(),
            req.url(),
            response.status_code().0
        );

        let _ = req.respond(response);
    }
}

fn get_response(req: &mut Request, printer: &mut Printer<UsbDriver>, app: &App) -> ResponseBox {
    let url = req.url();

    if let Some((_, path)) = url.split_once("/") {
        let path = if let Some((path, __)) = path.split_once('?') {
            path
        } else {
            path
        };
        match path {
            "editorjs.mjs" | "header.mjs" | "pell.js" => {
                let content = fs::read(path).unwrap();
                return Response::from_data(content)
                    .with_header(
                        Header::from_bytes(&b"Content-Type"[..], &b"application/javascript"[..])
                            .unwrap(),
                    )
                    .with_status_code(200)
                    .boxed();
            }
            "receipt.jpg" => {
                let content = fs::read(path).unwrap();
                return Response::from_data(content)
                    .with_header(
                        Header::from_bytes(&b"Content-Type"[..], &b"image/jpeg"[..]).unwrap(),
                    )
                    .with_status_code(200)
                    .boxed();
            }
            "" | "index.html" => {
                return serve_page_if_logged_in(req, &app);
            }
            "favicon.ico" => {
                return Response::from_data(include_bytes!("../favicon.ico"))
                    .with_status_code(200)
                    .boxed();
            }
            "discord-auth" => {
                return discord_auth_api(req, printer, &app);
            }
            "api/acceptRequest" => {
                return accept_request_api(req, app);
            }
            "api/print" => {
                return print_api(req, printer, app);
            }
            _ => {}
        }
    }

    Response::from_string("Not found")
        .with_status_code(404)
        .boxed()
}

fn accept_request_api(req: &mut Request, app: &App) -> ResponseBox {
    let url = url::Url::parse(&format!("http://localhost/{}", req.url())).unwrap();
    let code = try_unwrap!(
        url.query_pairs()
            .find_map(|(k, v)| (k == "code").then(|| v))
            .ok_or("Failed to find 'code' param")
    );

    let mut user = try_unwrap!(
        app.db
            .get_user_by_code(&*code)
            .ok_or(anyhow::anyhow!("No such code"))
    );

    user.authorize_secret = None;

    app.db.update_user(user);

    return Response::empty(30)
        .with_status_code(303)
        .with_header(Header::from_bytes(&b"Location"[..], "/").unwrap())
        .boxed();
}

fn serve_page_if_logged_in(req: &mut Request, app: &App) -> ResponseBox {
    if let Some(jwt) = get_jwt_cookie(req, app) {
        let user = try_unwrap!(
            app.db
                .get_user(jwt.discord_id)
                .ok_or(anyhow::anyhow!("no user found"))
        );
        if user.authorize_secret.is_none() {
            let content = fs::read("index.html").unwrap();
            return Response::from_data(content).with_status_code(200).boxed();
        }
    }

    let content = fs::read_to_string("auth.html").unwrap();
    let content = content.replace("{{AUTH_URL}}", &app.discord_auth_uri);
    return Response::from_data(content).with_status_code(200).boxed();
}

fn discord_auth_api(req: &mut Request, printer: &mut Printer<UsbDriver>, app: &App) -> ResponseBox {
    let url = url::Url::parse(&format!("http://localhost/{}", req.url())).unwrap();
    let code = try_unwrap!(
        url.query_pairs()
            .find_map(|(k, v)| (k == "code").then(|| v))
            .ok_or("Failed to find 'code' param")
    );

    let discord_user = try_unwrap!(get_discord_user(code, app));

    // add user to DB

    let secret: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let user = User {
        user_id: discord_user.id.get(),
        username: discord_user.name.clone(),
        prints_left: 10,
        authorize_secret: Some(secret.clone()),
    };
    app.db.update_user(user);

    let authorize_url = format!("https://fax.fnk.ee/api/acceptRequest?code={}", secret);

    debug!(
        "User {} wants to auth. Go to {} to accept",
        discord_user.name, authorize_url
    );
    if let Err(e) = send_auth_request_print_qr(&discord_user, authorize_url, printer) {
        log::error!("Failed to print receipt for authorize: {e:?}");
    }

    let jwt = FaxJwt {
        discord_id: discord_user.id.get(),
        discord_name: discord_user.name.clone(),
        exp: 0,
    };

    // set the auth:ed cookie in the response and redirect to home
    let jwt = try_unwrap!(jsonwebtoken::encode(
        &jsonwebtoken::Header::new(Algorithm::HS256),
        &jwt,
        &app.jwt_encode_key
    ));

    let cookie = CookieBuilder::new("auth", jwt)
        .http_only(true)
        .same_site(cookie::SameSite::Strict)
        .build();

    return Response::empty(303)
        .with_header(Header::from_bytes(&b"Set-Cookie"[..], cookie.to_string().as_bytes()).unwrap())
        .with_header(Header::from_bytes(&b"Location"[..], "/").unwrap())
        .boxed();
}

fn send_auth_request_print_qr(
    discord_user: &CurrentUser,
    authorize_url: String,
    printer: &mut Printer<UsbDriver>,
) -> anyhow::Result<()> {
    printer.feed()?;
    printer.size(2, 2)?;
    printer.write("Received request from '")?;
    printer.bold(true)?;
    printer.write(&discord_user.name)?;
    printer.bold(false)?;
    printer.write("' (")?;
    printer.write(&discord_user.id.get().to_string())?;
    printer.writeln(")")?;
    printer.feed()?;

    printer.writeln("Scan the code to authorize printer access");

    printer.feed()?;

    printer.qrcode_option(
        &authorize_url,
        QRCodeOption::new(QRCodeModel::Model2, 5, QRCodeCorrectionLevel::H),
    )?;

    printer.feed()?;

    printer.print_cut()?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct OauthResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: String,
    scope: String,
}

fn get_discord_user(code: std::borrow::Cow<'_, str>, app: &App) -> anyhow::Result<CurrentUser> {
    // get access token
    debug!("Using code: {code}");
    let form: [(&str, &str); 6] = [
        ("client_id", &app.discord_client_id),
        ("client_secret", &app.discord_client_secret),
        ("code", &*code),
        ("grant_type", "authorization_code"),
        ("redirect_uri", &app.redirect_uri),
        ("scope", "identify"),
    ];
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = agent
        .post("https://discord.com/api/oauth2/token")
        .send_form(form)?;
    if !response.status().is_success() {
        log::error!(
            "Failed to call discord oauth: {}",
            response.body_mut().read_to_string()?
        );
        return Err(anyhow::anyhow!(""));
    }
    let body: OauthResponse = response.body_mut().read_json()?;

    let access_token = format!("{} {}", body.token_type, body.access_token);

    // get self
    let user_client = Http::new(&access_token);
    let me = app.rt.block_on(user_client.get_current_user())?;

    debug!("Received printer access request from: {me:?}");

    Ok(me)
}

fn print(text: Text, printer: &mut Printer<UsbDriver>, jwt: FaxJwt) -> anyhow::Result<()> {
    let html = Dom::parse(&text.text)?;

    print_nodes_recursively(printer, html.children)?;

    printer.feed()?;
    printer.feed()?;
    printer.size(2, 2)?;
    printer.write("Sent by ")?;
    printer.bold(true)?;
    printer.writeln(&jwt.discord_name)?;
    printer.feed()?;
    printer.feed()?;

    printer.print_cut()?;

    Ok(())
}

fn print_nodes_recursively(
    printer: &mut Printer<UsbDriver>,
    children: Vec<html_parser::Node>,
) -> anyhow::Result<()> {
    for node in children {
        match node {
            html_parser::Node::Text(txt) => print_text(printer, &txt)?,
            html_parser::Node::Element(element) => {
                match element.name.as_str() {
                    "h1" => {
                        printer.size(4, 4)?;
                    }
                    "h2" => {
                        printer.size(3, 3)?;
                    }
                    "div" => {
                        printer.size(2, 2)?;
                    }
                    "br" => {
                        printer.feed()?;
                    }
                    "hr" => {
                        printer.feed()?;

                        printer.draw_line(
                            LineBuilder::new()
                                .font(Font::A)
                                .size((1, 1))
                                .justify(JustifyMode::CENTER)
                                .style(LineStyle::Dashed)
                                .width(30)
                                .build(),
                        )?;
                        printer.feed()?;
                    }
                    _ => {}
                };
                print_nodes_recursively(printer, element.children)?;
                match element.name.as_str() {
                    "div" | "h1" | "h2" => {
                        printer.feed()?;
                    }
                    _ => {}
                };
            }
            html_parser::Node::Comment(_) => todo!(),
        }
    }
    Ok(())
}

fn print_text(printer: &mut Printer<UsbDriver>, txt: &str) -> anyhow::Result<()> {
    if txt.len() == 0 {
        return Ok(());
    }
    for part in split_urls(&txt) {
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
    text: String,
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

fn print_api(request: &mut Request, printer: &mut Printer<UsbDriver>, app: &App) -> ResponseBox {
    let jwt = match get_jwt_cookie(&request, app) {
        Some(jwt) => jwt,
        None => {
            return Response::from_string("{'reason':'missing JWT cookie'}")
                .with_status_code(401)
                .boxed();
        }
    };
    let r: Text = crate::try_json!(request);

    let mut user = try_unwrap!(
        app.db
            .get_user(jwt.discord_id)
            .ok_or(anyhow::anyhow!("No such user"))
    );

    debug!(
        "{} wants to print {} characters, {} prints left",
        jwt.discord_name,
        r.text.len(),
        user.prints_left
    );

    if r.text.len() >= 2000 {
        log::debug!("Too many characters!");
        return Response::from_string("{'reason':'too much data'}")
            .with_status_code(400)
            .boxed();
    }

    if user.prints_left <= 0 {
        log::debug!("No more prints left!");
        return Response::from_string("{'reason':'no more prints left'}")
            .with_status_code(503)
            .boxed();
    }

    if user.authorize_secret.is_some() {
        log::debug!("user not authorized!");
        return Response::from_string("{'reason':'not authorized'}")
            .with_status_code(403)
            .boxed();
    }

    match print(r, printer, jwt) {
        Ok(()) => {
            user.prints_left -= 1;
            app.db.update_user(user);
            return Response::empty(200).boxed();
        }
        Err(e) => {
            return Response::from_string(format!("{e:?}"))
                .with_status_code(500)
                .boxed();
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FaxJwt {
    discord_id: u64,
    discord_name: String,
    exp: usize,
}

struct App {
    discord_client_id: String,
    discord_client_secret: String,
    discord_bot_client: Http,
    jwt_decode_key: DecodingKey,
    jwt_encode_key: EncodingKey,
    redirect_uri: String,
    discord_auth_uri: String,
    rt: tokio::runtime::Runtime,
    db: Database,
}

pub fn get_jwt_cookie(req: &Request, app: &App) -> Option<FaxJwt> {
    let Some(header) = req
        .headers()
        .iter()
        .find(|h| h.field == "Cookie".parse().unwrap())
    else {
        log::warn!("No cookies found");
        return None;
    };

    let auth_cookie = Cookie::split_parse(header.value.as_str())
        .filter_map(|c| c.ok())
        .find(|c| c.name() == "auth")?;

    let validation = {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation
    };

    let jwt: FaxJwt =
        match jsonwebtoken::decode(auth_cookie.value(), &app.jwt_decode_key, &validation) {
            Ok(jwt) => jwt.claims,
            Err(e) => {
                log::error!("Failed to parse JWT: {e}");
                return None;
            }
        };

    Some(jwt)
}
