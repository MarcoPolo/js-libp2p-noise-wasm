use core::future::Future;
use futures::future::BoxFuture;
use futures::ready;
use futures::{AsyncRead, AsyncWrite, FutureExt};
use js_sys::Promise;
use libp2p_core::{
    identity::{self, Keypair},
    InboundUpgrade, OutboundUpgrade,
};
use libp2p_noise::{LegacyConfig, NoiseConfig, X25519Spec};
use std::pin::Pin;
use std::{
    io,
    io::Write,
    task::{Context, Poll},
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    pub type Stream;

    #[wasm_bindgen(method, catch)]
    async fn read_ready(this: &Stream) -> Result<(), JsValue>;

    #[wasm_bindgen(method, catch)]
    fn read(this: &Stream, buf: &mut [u8]) -> Result<usize, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn write(this: &Stream, buf: &[u8]) -> Result<JsValue, JsValue>;
}

#[wasm_bindgen]
pub async fn upgrade_outbound(mut stream: Stream) {
    console_error_panic_hook::set_once();
    let mut zero_bytes = [0u8; 32];
    let kp: identity::Keypair = identity::Keypair::Ed25519(
        identity::ed25519::SecretKey::from_bytes(&mut zero_bytes)
            .expect("Should decode")
            .into(),
    );

    let client_dh = libp2p_noise::Keypair::<X25519Spec>::new()
        .into_authentic(&kp)
        .unwrap();

    let nc = NoiseConfig::xx(client_dh);

    let wrapped_stream = WrappedStream {
        s: std::rc::Rc::new(stream),
        write_fut: None,
        read_ready_fut: None,
    };

    log(&format!("here out 1"));
    match nc.upgrade_outbound(wrapped_stream, &[]).await {
        Ok(_) => log("outbound: Done with upgrade"),
        Err(e) => log(&format!("outbound: Err with upgrade: {:?}", e)),
    }

    // log(&format!("here!"));
}

#[wasm_bindgen]
pub async fn upgrade_inbound(mut stream: Stream) {
    console_error_panic_hook::set_once();
    let mut one_bytes = [1u8; 32];
    let kp: identity::Keypair = identity::Keypair::Ed25519(
        identity::ed25519::SecretKey::from_bytes(&mut one_bytes)
            .expect("Should decode")
            .into(),
    );

    let client_dh = libp2p_noise::Keypair::<X25519Spec>::new()
        .into_authentic(&kp)
        .unwrap();

    let nc = NoiseConfig::xx(client_dh);

    let wrapped_stream = WrappedStream {
        s: std::rc::Rc::new(stream),
        write_fut: None,
        read_ready_fut: None,
    };

    log(&format!("here in 1"));
    match nc.upgrade_inbound(wrapped_stream, &[]).await {
        Ok(_) => log("inbound: Done with upgrade"),
        Err(e) => log(&format!("inbound: Err with upgrade: {:?}", e)),
    }

    // log(&format!("read! {:?}", buf));
}

// rust-libp2p currently requires Send for inbound and outbound upgrades.
unsafe impl Send for WrappedStream {}

async fn write_helper(stream: std::rc::Rc<Stream>, buf: Vec<u8>) -> Result<usize, std::io::Error> {
    let res = stream.write(&buf).await;
    res.map(|data| data.as_f64().unwrap() as usize)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Write error"))
}

async fn read_ready_helper(stream: std::rc::Rc<Stream>) -> Result<(), std::io::Error> {
    let res = stream.read_ready().await;
    res.map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Read ready error: {:?}", e.as_string()),
        )
    })
}

struct WrappedStream {
    s: std::rc::Rc<Stream>,
    write_fut: Option<Pin<Box<dyn Future<Output = Result<usize, std::io::Error>>>>>,
    read_ready_fut: Option<Pin<Box<dyn Future<Output = Result<(), std::io::Error>>>>>,
}

/// Wrapper around a sync stream that will provide an async interface
impl<'a> AsyncWrite for WrappedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_fut.is_none() {
            self.write_fut = Some(Box::pin(write_helper(self.s.clone(), buf.into())));
            // self.write_fut = Some(Box::pin(write_intermediate(&self.s, buf.into())));
        }

        let v = ready!(self.write_fut.as_mut().unwrap().poll_unpin(cx));
        self.write_fut.take();
        return Poll::Ready(v);
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Not implemented. We assume _we_ don't need to close this
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for WrappedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.read_ready_fut.is_none() {
            self.read_ready_fut = Some(Box::pin(read_ready_helper(self.s.clone())));
        }
        let v = ready!(self.read_ready_fut.as_mut().unwrap().poll_unpin(cx));
        _ = self.read_ready_fut.take();

        match v {
            Ok(()) => {
                return Poll::Ready(Ok(self.s.read(buf).map_err(|_e| {
                    std::io::Error::new(std::io::ErrorKind::Other, "Read failed")
                })?));
            }
            Err(e) => return Poll::Ready(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
