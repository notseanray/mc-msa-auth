use anyhow::Error;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use std::io::Read;
use std::net::TcpListener;
use std::time::Duration;
use urlencoding::encode;

#[derive(Deserialize, Debug)]
pub struct TokenResponse {
    token_type: String,
    expires_in: u64,
    scope: String,
    access_token: String,
    refresh_token: String,
    user_id: String,
    // are these fields even used
    foci: Option<String>,
    error_description: Option<String>,
    error: Option<String>,
    correlation_id: Option<String>,
}

// todo: add from String from here to clean up code a bit
impl TokenResponse {}

#[derive(Deserialize, Debug)]
pub struct Uhs {
    uhs: String,
}

#[derive(Deserialize, Debug)]
pub struct DisplayClaims {
    xui: Vec<Uhs>,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case, dead_code)]
pub struct XBLResponse {
    IssueInstant: String,
    NotAfter: String,
    Token: String,
    DisplayClaims: DisplayClaims,
}

#[allow(dead_code)]
pub struct MicrosoftAuth<'a> {
    app_id: &'a str,
    app_secret: &'a str,
    redirect_url: &'a str,
    compiled_id: String,
    compiled_scope: String,
    compiled_url: String,
    compiled_secret: String,
    listener: Option<TcpListener>, // probably not needed
    auth_code: Option<String>,
}

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
pub struct XBLRequestProperties {
    AuthMethod: String,
    SiteName: String,
    RpsTicket: String,
}

impl XBLRequestProperties {
    pub fn new(access_token: &str) -> Self {
        Self {
            AuthMethod: "RPS".to_string(),
            SiteName: "user.auth.xboxlive.com".to_string(),
            RpsTicket: format!("d={access_token}"),
        }
    }
}

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
struct XBLRequestBody {
    Properties: XBLRequestProperties,
    RelyingParty: String,
    TokenType: String,
}

impl XBLRequestBody {
    pub fn new(access_token: &str) -> Self {
        Self {
            Properties: XBLRequestProperties::new(access_token),
            RelyingParty: "http://auth.xboxlive.com".to_string(),
            TokenType: "JWT".to_string(),
        }
    }
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct XSTSResponse {
    IssueInstant: String,
    NotAfter: String,
    Token: String,
    DisplayClaims: DisplayClaims,
}

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
pub struct XSTSRequestProperties {
    SandboxId: String,
    UserTokens: Vec<String>,
}

impl XSTSRequestProperties {
    pub fn new(xbl_token: &str) -> Self {
        Self {
            SandboxId: "RETAIL".to_string(),
            UserTokens: vec![xbl_token.to_string()],
        }
    }
}

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
pub struct XSTSRequestBody {
    Properties: XSTSRequestProperties,
    RelyingParty: String,
    TokenType: String,
}

impl XSTSRequestBody {
    pub fn new(xbl_token: &str) -> Self {
        Self {
            Properties: XSTSRequestProperties::new(xbl_token),
            RelyingParty: "rp://api.minecraftservices.com/".to_string(),
            TokenType: "JWT".to_string(),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct MCTokenResponse {
    username: String,
    roles: Vec<String>,
    access_token: String,
    token_type: String,
    expires_in: u64,
}

#[derive(Deserialize, Debug)]
pub struct Skin {
    id: String,
    state: String,
    url: String,
    variant: String,
    alias: String,
}

#[derive(Deserialize, Debug)]
pub struct Cape {
    id: String,
    state: String,
    url: String,
    alias: String,
}

#[derive(Deserialize, Debug)]
pub struct MCProfileResponse {
    id: String,
    name: String,
    skins: Vec<Skin>,
    capes: Vec<Cape>,
}

impl<'a> MicrosoftAuth<'a> {
    const SCOPE: &'static str = "XboxLive.signin offline_access";
    const TOKEN_URL: &'static str = "https://login.live.com/oauth20_token.srf";
    const AUTH_URL: &'static str = "https://user.auth.xboxlive.com/user/authenticate";
    const XSTS_AUTH: &'static str = "https://xsts.auth.xboxlive.com/xsts/authorize";
    const MC_TOKEN_URL: &'static str =
        "https://api.minecraftservices.com/authentication/login_with_xbox";
    const PROFILE_URL: &'static str = "https://api.minecraftservices.com/minecraft/profile";

    pub fn new(app_id: &'a str, app_secret: &'a str, redirect_url: &'a str) -> Self {
        Self {
            compiled_id: encode(app_id).to_string(),
            compiled_scope: encode(Self::SCOPE).to_string(),
            compiled_url: encode(redirect_url).to_string(),
            compiled_secret: encode(app_secret).to_string(),
            app_id,
            app_secret,
            redirect_url,
            listener: None,
            auth_code: None,
        }
    }
    pub fn create_url(&self) -> String {
        format!("https://login.live.com/oauth20_authorize.srf?client_id={}&response_type=code&redirect_uri={}&scope={}", self.compiled_id, self.compiled_url, self.compiled_scope)
    }
    // todo result
    pub fn listen_for_code(&mut self, port: u16) -> Result<String, Error> {
        if let Ok(v) = TcpListener::bind("localhost:".to_string() + &port.to_string()) {
            println!("started server on 0.0.0.0:8080");
            if let Some(mut stream) = v.incoming().flatten().next() {
                let mut buf: Vec<u8> = Vec::with_capacity(1024);
                stream.read_to_end(&mut buf)?;
                // add more verification to this
                let response = String::from_utf8_lossy(&buf).to_string();
                let code = response.split("?code=").collect::<Vec<&str>>()[1]
                    .split(' ')
                    .collect::<Vec<&str>>()[0]
                    .to_string();
                self.auth_code = Some(code.to_owned());
                return Ok(code);
            }
            self.listener = Some(v);
        } else {
            println!("fail");
        }
        Ok("piss".to_string())
    }

    pub fn auth_flow(&mut self) -> Result<()> {
        let token = self.get_token(self.auth_code.clone().expect("must listen for code before"))?;
        let body = serde_json::to_string(&XBLRequestBody::new(&token.access_token)).unwrap();
        let client = reqwest::blocking::Client::new();
        let mut buffer = String::new();
        // add timeout and add safety
        let _ = client
            .post(Self::AUTH_URL)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body)
            .timeout(Duration::from_millis(500))
            .send()
            .unwrap()
            .read_to_string(&mut buffer);
        println!("{}", buffer);
        let xbl_res: XBLResponse = serde_json::from_str(&buffer).expect("invalid xbl res");
        println!("{:?}", xbl_res);
        // authXSTS
        let mut buffer = String::new();
        let body = serde_json::to_string(&XSTSRequestBody::new(&xbl_res.Token)).unwrap();
        let _ = client
            .post(Self::XSTS_AUTH)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body)
            .timeout(Duration::from_millis(500))
            .send()
            .unwrap()
            .read_to_string(&mut buffer);
        println!("{}", buffer);
        let xsts_res: XSTSResponse = serde_json::from_str(&buffer).expect("invalid xsts");
        println!("{:?}", xsts_res);
        // getMinecraftToken
        // todo add safety check
        let mut buffer = String::new();
        let body = format!(
            "{{\"identityToken\":\"XBL3.0 x={};{}\"}}",
            xbl_res.DisplayClaims.xui[0].uhs, xsts_res.Token
        );
        let _ = client
            .post(Self::MC_TOKEN_URL)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body)
            .timeout(Duration::from_millis(500))
            .send()
            .unwrap()
            .read_to_string(&mut buffer);
        println!("{}", buffer);
        let mc_token: MCTokenResponse =
            serde_json::from_str(&buffer).expect("invalid token resposen");
        let mut buffer = String::new();
        let _ = client
            .get(Self::PROFILE_URL)
            .header(
                "Authorization",
                &format!("Bearer {}", mc_token.access_token),
            )
            .timeout(Duration::from_millis(500))
            .send()
            .unwrap()
            .read_to_string(&mut buffer);
        println!("{}", buffer);
        let mc_profile: MCProfileResponse =
            serde_json::from_str(&buffer).expect("invalid mc profile response");
        println!("{:?}", mc_profile);
        Ok(())
    }

    // add timeout in header
    fn get_token(&mut self, auth_code: String) -> Result<TokenResponse, Error> {
        let body = format!(
            "client_id={}&client_secret={}&code={}&grant_type=authorization_code&redirect_uri={}",
            self.compiled_id, self.compiled_secret, auth_code, self.compiled_url
        );
        let client = reqwest::blocking::Client::new();
        let mut buffer = String::new();
        let _ = client
            .post(Self::TOKEN_URL)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .timeout(Duration::from_millis(500))
            .send()
            .unwrap()
            .read_to_string(&mut buffer)?;
        // need more safety checks here
        println!("{}", buffer);
        let token_response: TokenResponse = serde_json::from_str(&buffer).unwrap();
        Ok(token_response)
    }
}
