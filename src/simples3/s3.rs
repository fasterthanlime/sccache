// Originally from https://github.com/rust-lang/crates.io/blob/master/src/s3/lib.rs
//#![deny(warnings)]

#[allow(unused_imports, deprecated)]
use std::ascii::AsciiExt;
use std::fmt;

use crate::simples3::credential::*;
use futures::{Future, Stream};
use http::header::HeaderName;
use hyper::header::HeaderValue;
use hyper::Method;
use hyperx::header;
use reqwest::r#async::{Client, Request};
use rusoto_signature::Region;
use rusoto_signature::SignedRequest;

use crate::errors::*;
use crate::util::HeadersExt;

#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
/// Whether or not to use SSL.
pub enum Ssl {
    /// Use SSL.
    Yes,
    /// Do not use SSL.
    No,
}

/// An S3 bucket.
pub struct Bucket {
    name: String,
    region: Region,
    client: Client,
    server_side_encryption: Option<String>,
}

impl fmt::Display for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bucket(name={}, region={:?})", self.name, self.region)
    }
}

impl Bucket {
    pub fn new(
        name: &str,
        region: Option<&str>,
        endpoint: Option<&str>,
        server_side_encryption: Option<&str>,
    ) -> Result<Bucket> {
        let region = if let Some(endpoint) = endpoint {
            Region::Custom {
                name: "custom".into(),
                endpoint: endpoint.into(),
            }
        } else if let Some(region) = region {
            region.parse().map_err(|err| {
                HttpClientError(format!("Invalid AWS region: {}: {}", region, err))
            })?
        } else {
            Region::UsEast1
        };

        Ok(Bucket {
            name: name.to_owned(),
            region,
            client: Client::new(),
            server_side_encryption: server_side_encryption.map(|s| s.to_owned()),
        })
    }

    fn path(&self, key: &str) -> String {
        format!("/{}/{}", self.name, key)
    }

    pub fn get(&self, key: &str, creds: Option<&AwsCredentials>) -> SFuture<Vec<u8>> {
        let path = self.path(key);
        debug!("GET {}", key);
        let sr = SignedRequest::new("GET", "s3", &self.region, &path);

        let request = to_http_request(sr, creds.expect("wanted credentails"));
        let url = request.url().clone();
        let url2 = url.clone();

        Box::new(
            self.client
                .execute(request)
                .fwith_context(move || format!("failed GET: {}", url))
                .and_then(|res| {
                    if res.status().is_success() {
                        let content_length = res
                            .headers()
                            .get_hyperx::<header::ContentLength>()
                            .map(|header::ContentLength(len)| len);
                        Ok((res.into_body(), content_length))
                    } else {
                        Err(BadHttpStatusError(res.status()).into())
                    }
                })
                .and_then(|(body, content_length)| {
                    body.fold(Vec::new(), |mut body, chunk| {
                        body.extend_from_slice(&chunk);
                        Ok::<_, reqwest::Error>(body)
                    })
                    .fcontext("failed to read HTTP body")
                    .and_then(move |bytes| {
                        if let Some(len) = content_length {
                            if len != bytes.len() as u64 {
                                bail!(format!(
                                    "Bad HTTP body size read: {}, expected {}",
                                    bytes.len(),
                                    len
                                ));
                            } else {
                                info!("Read {} bytes from {}", bytes.len(), url2);
                            }
                        }
                        Ok(bytes)
                    })
                }),
        )
    }

    pub fn put(&self, key: &str, content: Vec<u8>, creds: &AwsCredentials) -> SFuture<()> {
        let path = self.path(key);
        debug!("PUT {}", path);

        let mut sr = SignedRequest::new("PUT", "s3", &self.region, &path);

        if let Some(sse) = &self.server_side_encryption {
            sr.add_header("x-amz-server-side-encryption", sse);
        }
        sr.set_payload(Some(content));

        let request = to_http_request(sr, creds);

        Box::new(self.client.execute(request).then(|result| match result {
            Ok(res) => {
                if res.status().is_success() {
                    trace!("PUT succeeded");
                    Ok(())
                } else {
                    trace!("PUT failed with HTTP status: {}", res.status());
                    let err = BadHttpStatusError(res.status()).into();

                    tokio_compat::runtime::current_thread::TaskExecutor::current()
                        .spawn_local({
                            res.into_body()
                                .fold(Vec::new(), |mut body, chunk| {
                                    body.extend_from_slice(&chunk);
                                    Ok::<_, reqwest::Error>(body)
                                })
                                .map_err(|e| {
                                    panic!("Could not read body: {}", e);
                                })
                                .and_then(|bytes: Vec<u8>| {
                                    trace!(
                                        "PUT S3 error: {}",
                                        std::str::from_utf8(&bytes[..]).unwrap()
                                    );
                                    Ok(())
                                })
                        })
                        .unwrap();
                    Err(err)
                }
            }
            Err(e) => {
                trace!("PUT failed with error: {:?}", e);
                Err(e.into())
            }
        }))
    }
}

fn to_http_request(mut sr: SignedRequest, creds: &AwsCredentials) -> Request {
    sr.complement();
    sr.sign(&rusoto_signature::credential::AwsCredentials::new(
        creds.aws_access_key_id(),
        creds.aws_secret_access_key(),
        creds.token().clone(),
        Some(*creds.expires_at()),
    ));

    let uri = format!(
        "{}://{}{}?{}",
        sr.scheme(),
        sr.hostname(),
        sr.canonical_uri,
        sr.canonical_query_string()
    );
    debug!("uri = {}", uri);

    let method = match sr.method() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        m => panic!("Unsupported method: {}", m),
    };

    let mut request = Request::new(method, uri.parse().unwrap());
    for (k, vv) in sr.headers() {
        for v in vv {
            request.headers_mut().insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_bytes(v).unwrap(),
            );
        }
    }
    debug!("request = {:#?}", request);

    if let Some(body) = sr.payload {
        match body {
            rusoto_signature::SignedRequestPayload::Buffer(body) => {
                *request.body_mut() = Some(body.to_vec().into())
            }
            rusoto_signature::SignedRequestPayload::Stream(_) => panic!(),
        }
    };

    request
}
