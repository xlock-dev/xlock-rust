# xlock

Rust SDK for [x-lock](https://x-lock.dev) bot protection.

## Install

```toml
[dependencies]
xlock = "0.1"
```

The `actix` feature is enabled by default. To use only the core `verify()` function without actix-web:

```toml
[dependencies]
xlock = { version = "0.1", default-features = false }
```

## Usage with actix-web

```rust
use xlock::{Config, XLock};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .wrap(XLock::new(Config {
                site_key: "sk_live_...".into(),
                protected_paths: vec!["/api/login".into(), "/api/signup".into()],
                ..Default::default()
            }))
            .route("/api/login", actix_web::web::post().to(login))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}

async fn login() -> impl actix_web::Responder {
    "ok"
}
```

The middleware reads the `x-lock` header from incoming POST requests and verifies it against the x-lock API. Requests without a valid token receive a `403 Forbidden` response.

## Direct verification

```rust
use xlock::{Config, default_client, verify};

async fn check_token(token: &str) {
    let client = default_client();
    let config = Config::default(); // reads XLOCK_SITE_KEY env var
    let result = verify(&client, &config, token, "/api/login").await;

    if result.blocked {
        println!("Blocked: {:?}", result.reason);
    }
}
```

## Configuration

| Field | Default | Description |
|---|---|---|
| `site_key` | `$XLOCK_SITE_KEY` | Your x-lock site key |
| `api_url` | `https://api.x-lock.dev` | API base URL |
| `fail_open` | `true` | Allow requests through on verification errors |
| `protected_paths` | `[]` | Path prefixes to protect (empty = all POSTs) |

## License

MIT
