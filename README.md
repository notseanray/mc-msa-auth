# mc-msa-auth
This is a way to authenticate with microsoft to get a minecraft token. This can be used for make custom clients, both headless or full clients. This project is made in rust, and is made for rust. 

## Example
This is an example of how you can get a minecraft token from the login method.

``` rust
use mc-msa-auth::MicrosoftAuth;

fn main(){
    let mut auth = MicrosoftAuth::new("CLIENT ID", "CLIENT SECRET", "http://localhost:{PORT}/token");
    println!("URL: {}", auth.create_url())
    let code = auth.listen_for_code(8080).unwrap();
    let token = auth.get_token(code);
    println!("Code: {}", token);
}
```

## Azure token
To get the the `client id` and the `client secret value` you can follow this step by step list.

* Goto [Azure Active Directory Overview](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Overview)
* Log in with your microsoft account
* Look in top and add a new registration
* Fill in name
* For Redirect URI choose web, and put in `http://localhost:{PORT}/token` where `{PORT}` is the port you want to use.
* Then you have the `client id` it is called `Application (client) ID`
* For the client secret you have to click on the `create client secret`
* When you get into that page you just click on the `new client secret`button and click add in the bottom
* Then your `client secret` is what is under the value name
* Copy that to a safe place, because you only see it once
* Now you have your `client id` and `client secret`


## Credits
This project was made by [notseanray](https://github.com/notseanray) with some help from [AFunkyMonk](https://github.com/AFunkyMonk).
Also credits to the project [Minecraft-auth](https://github.com/dommilosz/minecraft-auth) by [dommilosz](https://github.com/dommilosz). It is a similar project written in typescript, that was rewritten in rust for this project.
