use mc_msa_auth::MicrosoftAuth;

fn main() {
    println!("Hello, world!");
    let mut auth = MicrosoftAuth::new("CLIENT ID", "CLIENT SECRET", "http://localhost:{PORT}/token");
    println!("{}", auth.create_url());
    let _code = auth.listen_for_code(8080).unwrap();
    let _ = auth.auth_flow();
}
