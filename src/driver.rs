use std::{
    collections::VecDeque,
    io,
    mem::MaybeUninit,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use anyhow::anyhow;
use bytes::{BufMut, Bytes, BytesMut};

use crate::core::{ConnectParams, Core};

pub trait Transport: Unpin + Send + Sync + 'static {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>>;

    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>>;

    fn poll_flush(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

pub struct Driver<T: Transport> {
    state: Arc<Mutex<DriverState<T>>>,
}

impl<T: Transport> Future for Driver<T> {
    type Output = Result<(), io::Error>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut st = self.state.lock().unwrap();
        let mut keep_going = st.drive_commands()?;
        keep_going |= st.drive_write(cx)?;
        keep_going |= st.drive_read(cx)?;
        // TODO add drive_events to wait table

        if keep_going {
            cx.waker().wake_by_ref();
        }

        Poll::Pending
    }
}

pub(crate) struct DriverState<T: Transport> {
    waker: Option<Waker>,
    transport: T,
    commands: VecDeque<ClientCommand>,
    core: Core,
    current_send: Option<Bytes>,
    current_read: BytesMut,
    send_offset: usize,
}

impl<T: Transport> DriverState<T> {
    fn drive_commands(&mut self) -> io::Result<bool> {
        while let Some(command) = self.commands.pop_front() {
            match command {
                ClientCommand::Close => {
                    self.core.close().unwrap();
                }
            }
        }
        Ok(true)
    }

    fn drive_write(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        if self.current_send.is_none() {
            self.current_send = self.core.poll_write();
            self.send_offset = 0;
        }

        let buf = match &self.current_send {
            Some(b) => b,
            None => return Ok(false),
        };

        while self.send_offset < buf.len() {
            match Pin::new(&mut self.transport).poll_write(cx, &buf[self.send_offset..])? {
                Poll::Ready(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write returned 0 bytes",
                    ));
                }
                Poll::Ready(n) => self.send_offset += n,
                Poll::Pending => return Ok(false),
            }
        }

        match Pin::new(&mut self.transport).poll_flush(cx)? {
            Poll::Ready(()) => {}
            Poll::Pending => return Ok(false),
        }

        self.send_offset = 0;
        self.current_send = None;

        Ok(true)
    }

    fn drive_read(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        let mut progress = false;

        loop {
            if self.current_read.spare_capacity_mut().is_empty() {
                self.current_read.reserve(1024);
            }

            let spare: &mut [MaybeUninit<u8>] = self.current_read.spare_capacity_mut();

            let buf: &mut [u8] = unsafe { &mut *(spare as *mut [MaybeUninit<u8>] as *mut [u8]) };

            let n = {
                let transport = &mut self.transport;

                match Pin::new(transport).poll_read(cx, buf)? {
                    Poll::Ready(0) => {
                        return Ok(true);
                    }
                    Poll::Ready(s) => s,
                    Poll::Pending => break,
                }
            };

            unsafe {
                self.current_read.advance_mut(n);
            }

            progress = true;
        }

        if progress {
            let current = std::mem::take(&mut self.current_read).freeze();
            self.core.handle(current);
            return Ok(true);
        }

        return Ok(false);
    }
}

pub(crate) enum ClientCommand {
    Close,
}
