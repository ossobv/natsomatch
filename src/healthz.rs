use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex}; // TokioMutex only needed if we await with lock held

use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming as IncomingBody, Request, Response, StatusCode};
use hyper::header::HeaderValue;
use hyper::service::Service;

use crate::stats;


#[derive(Clone)]
pub struct HealthzService {
    period_stats: Arc<Mutex<stats::Stats>>,
    forever_stats: Arc<Mutex<stats::Stats>>,
}

impl HealthzService {
    pub fn create(period_stats: Arc<Mutex<stats::Stats>>, forever_stats: Arc<Mutex<stats::Stats>>) -> HealthzService {
        HealthzService {
            period_stats,
            forever_stats,
        }
    }
}

impl Service<Request<IncomingBody>> for HealthzService {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<IncomingBody>) -> Self::Future {
        fn mk_response(s: String, status: StatusCode) -> Result<Response<Full<Bytes>>, hyper::Error> {
            let mut response = Response::builder()
                .status(status)
                .body(Full::new(Bytes::from(s)))
                .unwrap();
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"));
            Ok(response)
        }

        if req.uri().path() != "/healthz" {
            return Box::pin(async { mk_response("Not Found\n".into(), StatusCode::NOT_FOUND) });
        }

        let forever_stats = self.forever_stats.lock().expect("Lock healthz.forever_stats fail");
        let period_stats = self.period_stats.lock().expect("Lock healthz.period_stats fail");

        let is_healthy = forever_stats.get_count() > 0 && forever_stats.get_last_publish() < 10;

        let body = format!(
            "{{\"since_start\":{},\"last_period\":{}}}\n",
            forever_stats.as_json(), period_stats.as_json());

        drop(forever_stats);
        drop(period_stats);

        let status_code = if is_healthy { StatusCode::OK } else { StatusCode::INTERNAL_SERVER_ERROR };
        Box::pin(async move { mk_response(body, status_code) })
    }
}
