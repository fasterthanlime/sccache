// Originally from https://github.com/rust-lang/crates.io/blob/master/src/s3/lib.rs
//#![deny(warnings)]

#[allow(unused_imports, deprecated)]
use std::ascii::AsciiExt;
use std::fmt;

use crate::simples3::credential::*;
use futures::{Future, Stream};
use hmac::{Hmac, Mac, NewMac};
use http::header::HeaderName;
use hyper::header::HeaderValue;
use hyper::Method;
use hyperx::header;
use reqwest::r#async::{Client, Request};
use rusoto_signature::Region;
use rusoto_signature::SignedRequest;
use sha1::Sha1;

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

fn base_url(endpoint: &str, ssl: Ssl) -> String {
    format!(
        "{}://{}/",
        match ssl {
            Ssl::Yes => "https",
            Ssl::No => "http",
        },
        endpoint
    )
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::<Sha1>::new_varkey(key).expect("HMAC can take key of any size");
    hmac.update(data);
    hmac.finalize().into_bytes().as_slice().to_vec()
}

fn signature(string_to_sign: &str, signing_key: &str) -> String {
    let s = hmac(signing_key.as_bytes(), string_to_sign.as_bytes());
    base64::encode_config(&s, base64::STANDARD)
}

/// An S3 bucket.
pub struct Bucket {
    name: String,
    base_url: String,
    client: Client,
}

impl fmt::Display for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bucket(name={}, base_url={})", self.name, self.base_url)
    }
}

impl Bucket {
    pub fn new(name: &str, endpoint: &str, ssl: Ssl) -> Result<Bucket> {
        let base_url = base_url(&endpoint, ssl);
        Ok(Bucket {
            name: name.to_owned(),
            base_url,
            client: Client::new(),
        })
    }

    pub fn get(&self, key: &str, creds: Option<&AwsCredentials>) -> SFuture<Vec<u8>> {
        let url = format!("{}{}", self.base_url, key);
        debug!("GET {}", url);

        Box::new(futures::future::err(
            BadHttpStatusError(http::StatusCode::IM_A_TEAPOT).into(),
        ))

        // let url2 = url.clone();
        // let mut request = Request::new(Method::GET, url.parse().unwrap());
        // if let Some(creds) = creds {
        //     let mut canonical_headers = String::new();

        //     if let Some(token) = creds.token().as_ref().map(|s| s.as_str()) {
        //         request.headers_mut().insert(
        //             "x-amz-security-token",
        //             HeaderValue::from_str(token).expect("Invalid `x-amz-security-token` header"),
        //         );
        //         canonical_headers
        //             .push_str(format!("{}:{}\n", "x-amz-security-token", token).as_ref());
        //     }
        //     let date = chrono::offset::Utc::now().to_rfc2822();
        //     let auth = self.auth("GET", &date, key, "", &canonical_headers, "", creds);
        //     request.headers_mut().insert(
        //         "Date",
        //         HeaderValue::from_str(&date).expect("Invalid date header"),
        //     );
        //     request.headers_mut().insert(
        //         "Authorization",
        //         HeaderValue::from_str(&auth).expect("Invalid authentication"),
        //     );
        // }

        // Box::new(
        //     self.client
        //         .execute(request)
        //         .fwith_context(move || format!("failed GET: {}", url))
        //         .and_then(|res| {
        //             if res.status().is_success() {
        //                 let content_length = res
        //                     .headers()
        //                     .get_hyperx::<header::ContentLength>()
        //                     .map(|header::ContentLength(len)| len);
        //                 Ok((res.into_body(), content_length))
        //             } else {
        //                 Err(BadHttpStatusError(res.status()).into())
        //             }
        //         })
        //         .and_then(|(body, content_length)| {
        //             body.fold(Vec::new(), |mut body, chunk| {
        //                 body.extend_from_slice(&chunk);
        //                 Ok::<_, reqwest::Error>(body)
        //             })
        //             .fcontext("failed to read HTTP body")
        //             .and_then(move |bytes| {
        //                 if let Some(len) = content_length {
        //                     if len != bytes.len() as u64 {
        //                         bail!(format!(
        //                             "Bad HTTP body size read: {}, expected {}",
        //                             bytes.len(),
        //                             len
        //                         ));
        //                     } else {
        //                         info!("Read {} bytes from {}", bytes.len(), url2);
        //                     }
        //                 }
        //                 Ok(bytes)
        //             })
        //         }),
        // )
    }

    pub fn put(&self, key: &str, content: Vec<u8>, creds: &AwsCredentials) -> SFuture<()> {
        let url = format!("{}{}", self.base_url, key);
        debug!("PUT {}", url);

        let now = chrono::offset::Utc::now();
        let date = now.to_rfc2822();

        let mut sr = SignedRequest::new(
            "PUT",
            "s3",
            &Region::UsEast2,
            &format!("/{}/{}", self.name, key),
        );

        sr.add_optional_header("x-amz-security-token", creds.token().as_deref());
        sr.add_header("x-amz-server-side-encryption", "AES256");
        sr.add_header("date", &date);
        sr.add_header("content-type", "application/octet-stream");
        sr.add_header("content-length", &content.len().to_string());
        sr.set_payload(Some(content));
        sr.sign(&rusoto_signature::credential::AwsCredentials::new(
            creds.aws_access_key_id(),
            creds.aws_secret_access_key(),
            creds.token().clone(),
            Some(*creds.expires_at()),
        ));

        for (k, vv) in sr.headers() {
            for v in vv {
                trace!("header: {} = {:?}", k, std::str::from_utf8(&v[..]));
            }
        }

        let uri = format!(
            "{}://{}{}?{}",
            sr.scheme(),
            sr.hostname(),
            sr.canonical_uri,
            sr.canonical_query_string()
        );
        debug!("uri = {}", uri);

        let mut request = Request::new(Method::PUT, uri.parse().unwrap());
        for (k, vv) in sr.headers() {
            for v in vv {
                request.headers_mut().insert(
                    HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    HeaderValue::from_bytes(v).unwrap(),
                );
            }
        }
        debug!("request = {:#?}", request);

        let payload = match sr.payload.unwrap() {
            rusoto_signature::SignedRequestPayload::Buffer(body) => body,
            rusoto_signature::SignedRequestPayload::Stream(_) => panic!(),
        };
        *request.body_mut() = Some(payload.to_vec().into());

        // let mut request = Request::new(Method::PUT, url.parse().unwrap());

        // let content_type = "application/octet-stream";
        // let now = chrono::offset::Utc::now();
        // let date = now.to_rfc2822();
        // let mut canonical_headers = String::new();
        // let token = creds.token().as_ref().map(|s| s.as_str());
        // // Keep the list of header values sorted!
        // for (header, maybe_value) in &[
        //     ("x-amz-security-token", token),
        //     ("x-amz-server-side-encryption", Some("AES256")),
        // ] {
        //     if let Some(ref value) = maybe_value {
        //         request.headers_mut().insert(
        //             *header,
        //             HeaderValue::from_str(value)
        //                 .unwrap_or_else(|_| panic!("Invalid `{}` header", header)),
        //         );
        //         canonical_headers
        //             .push_str(format!("{}:{}\n", header.to_ascii_lowercase(), value).as_ref());
        //     }
        // }

        // let auth = self.auth(
        //     "PUT",
        //     &date,
        //     key,
        //     "",
        //     &canonical_headers,
        //     content_type,
        //     creds,
        // );
        // request.headers_mut().insert(
        //     "Date",
        //     HeaderValue::from_str(&date).expect("Invalid date header"),
        // );
        // request
        //     .headers_mut()
        //     .set(header::ContentType(content_type.parse().unwrap()));
        // request
        //     .headers_mut()
        //     .set(header::ContentLength(content.len() as u64));
        // request.headers_mut().set(header::CacheControl(vec![
        //     // Two weeks
        //     header::CacheDirective::MaxAge(1_296_000),
        // ]));
        // request.headers_mut().insert(
        //     "Authorization",
        //     HeaderValue::from_str(&auth).expect("Invalid authentication"),
        // );
        // *request.body_mut() = Some(content.into());

        Box::new(self.client.execute(request).then(|result| match result {
            Ok(res) => {
                if res.status().is_success() {
                    trace!("PUT succeeded");
                    Ok(())
                } else {
                    trace!("PUT failed with HTTP status: {}", res.status());
                    let err = BadHttpStatusError(res.status()).into();

                    trace!("blocking on future...");
                    tokio_compat::runtime::current_thread::TaskExecutor::current()
                        .spawn_local({
                            trace!("Hello from beyond futures 0.1");
                            res.into_body()
                                .fold(Vec::new(), |mut body, chunk| {
                                    body.extend_from_slice(&chunk);
                                    Ok::<_, reqwest::Error>(body)
                                })
                                .map_err(|e| {
                                    panic!("Could not read body: {}", e);
                                })
                                .and_then(|bytes: Vec<u8>| {
                                    trace!("body = {}", std::str::from_utf8(&bytes[..]).unwrap());
                                    Ok(())
                                })
                        })
                        .unwrap();
                    trace!("blocking on future... done!");
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_signature() {
        assert_eq!(
            signature("/foo/bar\nbar", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            "mwbstmHPMEJjTe2ksXi5H5f0c8U="
        );

        assert_eq!(
            signature("/bar/foo\nbaz", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            "F9gZMso3+P+QTEyRKQ6qhZ1YM6o="
        );
    }
}
