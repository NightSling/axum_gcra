use std::{
    fmt::{self, Debug, Display},
    future,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    ops::Deref,
    str::FromStr,
    task::{Context, Poll},
};

use axum::{extract::FromRequestParts, response::IntoResponse};
use http::{header::HeaderName, request::Parts, HeaderValue, Request, StatusCode};
use tower::{Layer, Service};

/// Wrapper around [`std::net::IpAddr`] that can be extracted from the request parts.
///
/// This extractor tries to resolve the client's IP address from common proxy/load balancer headers,
/// falling back to the underlying socket (if `ConnectInfo` is enabled).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RealIp(pub IpAddr);

/// Like [`RealIp`], but with the last 64 bits of IPv6 addresses zeroed out.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RealIpPrivacyMask(pub RealIp);

impl From<RealIp> for RealIpPrivacyMask {
    #[inline]
    fn from(ip: RealIp) -> Self {
        match ip.0 {
            IpAddr::V4(v4) => RealIpPrivacyMask(RealIp(IpAddr::V4(v4))),
            IpAddr::V6(v6) => {
                let mut segments = v6.segments();
                // zero out lower 4 segments = last 64 bits
                segments[4] = 0;
                segments[5] = 0;
                segments[6] = 0;
                segments[7] = 0;
                RealIpPrivacyMask(RealIp(IpAddr::V6(std::net::Ipv6Addr::from(segments))))
            }
        }
    }
}

impl Debug for RealIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}
impl Display for RealIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}
impl Debug for RealIpPrivacyMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}
impl Display for RealIpPrivacyMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Deref for RealIp {
    type Target = IpAddr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Deref for RealIpPrivacyMask {
    type Target = RealIp;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// IP Address not found, returns 400.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpAddrRejection;

impl IntoResponse for IpAddrRejection {
    fn into_response(self) -> axum::response::Response {
        StatusCode::BAD_REQUEST.into_response()
    }
}

impl<S> FromRequestParts<S> for RealIp {
    type Rejection = IpAddrRejection;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        if let Some(ip) = parts.extensions.get::<RealIp>() {
            return future::ready(Ok(*ip));
        }
        future::ready(get_ip_from_parts(parts).ok_or(IpAddrRejection))
    }
}

impl<S> FromRequestParts<S> for RealIpPrivacyMask {
    type Rejection = IpAddrRejection;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        if let Some(ip) = parts.extensions.get::<RealIp>() {
            return future::ready(Ok((*ip).into()));
        }
        future::ready(get_ip_from_parts(parts).map(Into::into).ok_or(IpAddrRejection))
    }
}

/// Service that adds the [`RealIp`] extension.
#[derive(Debug, Clone, Copy)]
pub struct RealIpService<I>(I);

/// Layer that adds the [`RealIp`] extension.
#[derive(Debug, Clone, Copy)]
pub struct RealIpLayer;

impl<B, I> Service<Request<B>> for RealIpService<I>
where
    I: Service<Request<B>>,
{
    type Response = I::Response;
    type Error = I::Error;
    type Future = I::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let (mut parts, body) = req.into_parts();

        if let Some(ip) = get_ip_from_parts(&parts) {
            parts.extensions.insert(ip);
        }

        self.0.call(Request::from_parts(parts, body))
    }
}

impl<I> Layer<I> for RealIpLayer {
    type Service = RealIpService<I>;

    fn layer(&self, inner: I) -> Self::Service {
        RealIpService(inner)
    }
}

pub(crate) fn get_ip_from_parts(parts: &Parts) -> Option<RealIp> {
    fn parse_ip(val: &HeaderValue, allow_port: bool) -> Option<IpAddr> {
        let s = val.to_str().ok()?.trim();

        // Split on `,` for multi-hop headers (take the first entry)
        let first = s.split(',').next()?.trim();

        if allow_port {
            // Handle `IP:port` (CloudFront, some proxies)
            if let Ok(sock) = SocketAddr::from_str(first) {
                return Some(sock.ip());
            }
        }
        IpAddr::from_str(first).ok()
    }

    static HEADERS: [(HeaderName, bool); 10] = [
        (HeaderName::from_static("cf-connecting-ip"), false),
        (HeaderName::from_static("x-cluster-client-ip"), false),
        (HeaderName::from_static("fly-client-ip"), false),
        (HeaderName::from_static("fastly-client-ip"), false),
        (HeaderName::from_static("cloudfront-viewer-address"), true), // IP:port
        (HeaderName::from_static("x-real-ip"), false),
        (HeaderName::from_static("x-forwarded-for"), false), // may contain list
        (HeaderName::from_static("x-original-forwarded-for"), false),
        (HeaderName::from_static("true-client-ip"), false),
        (HeaderName::from_static("client-ip"), false),
    ];

    for (header, allow_port) in &HEADERS {
        if let Some(val) = parts.headers.get(header) {
            if let Some(ip) = parse_ip(val, *allow_port) {
                return Some(RealIp(ip));
            }
        }
    }

    #[cfg(feature = "tokio")]
    if let Some(info) = parts.extensions.get::<axum::extract::ConnectInfo<SocketAddr>>() {
        return Some(RealIp(info.ip()));
    }

    None
}
