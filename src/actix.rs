//! Actix-web middleware for x-lock bot protection.

use actix_web::{
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    HttpResponse,
};
use futures::future::{ok, LocalBoxFuture, Ready};
use reqwest::Client;
use std::{rc::Rc, task::Poll};

use crate::{verify, Config};

/// Actix-web middleware that verifies incoming requests against the x-lock API.
///
/// ```rust,no_run
/// use xlock::{Config, XLock};
///
/// actix_web::HttpServer::new(move || {
///     actix_web::App::new()
///         .wrap(XLock::new(Config {
///             site_key: "sk_...".into(),
///             protected_paths: vec!["/api/auth".into()],
///             ..Default::default()
///         }))
/// });
/// ```
#[derive(Clone)]
pub struct XLock {
    config: Config,
    client: Client,
}

impl XLock {
    /// Create a new middleware instance with the given [`Config`].
    pub fn new(config: Config) -> Self {
        Self {
            client: crate::default_client(),
            config,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for XLock
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Transform = XLockMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(XLockMiddleware {
            service: Rc::new(service),
            config: self.config.clone(),
            client: self.client.clone(),
        })
    }
}

#[doc(hidden)]
pub struct XLockMiddleware<S> {
    service: Rc<S>,
    config: Config,
    client: Client,
}

impl<S, B> Service<ServiceRequest> for XLockMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, ctx: &mut core::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let config = self.config.clone();
        let client = self.client.clone();

        Box::pin(async move {
            // Only check POST requests when a site key is configured.
            if config.site_key.is_empty() || req.method() != "POST" {
                return service.call(req).await.map(|res| res.map_into_left_body());
            }

            // If protected_paths is set, skip paths that don't match.
            if !config.protected_paths.is_empty() {
                let path = req.path();
                if !config.protected_paths.iter().any(|p| path.starts_with(p)) {
                    return service.call(req).await.map(|res| res.map_into_left_body());
                }
            }

            // Extract the x-lock token from headers.
            let token = req
                .headers()
                .get("x-lock")
                .and_then(|v| v.to_str().ok())
                .map(String::from);

            let Some(token) = token else {
                let resp = HttpResponse::Forbidden()
                    .json(serde_json::json!({"error": "Blocked by x-lock: missing token"}));
                return Ok(req.into_response(resp).map_into_right_body());
            };

            let path = req.path().to_string();
            let result = verify(&client, &config, &token, &path).await;

            if result.blocked {
                let resp = HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Blocked by x-lock",
                    "reason": result.reason,
                }));
                return Ok(req.into_response(resp).map_into_right_body());
            }

            service.call(req).await.map(|res| res.map_into_left_body())
        })
    }
}
