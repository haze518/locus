use std::{
    collections::VecDeque,
    io,
    mem::MaybeUninit,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::{BufMut, Bytes, BytesMut};
use futures_core::Stream;

use crate::core::{Core, CoreEvent};

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
        let (keep_going, events_waker, closed) = {
            let mut st = self.state.lock().unwrap();
            let mut keep_going = st.drive_commands()?;
            keep_going |= st.drive_write(cx)?;
            keep_going |= st.drive_read(cx)?;

            let (de_keep_going, waker) = st.drive_events()?;
            keep_going |= de_keep_going;

            let events_waker = if st.closed {
                waker.or_else(|| st.events_waker.take())
            } else {
                waker
            };

            (keep_going, events_waker, st.closed)
        };

        if closed {
            if let Some(waker) = events_waker {
                waker.wake();
            }
            return Poll::Ready(Ok(()));
        }

        if let Some(waker) = events_waker {
            waker.wake();
        }

        if keep_going {
            cx.waker().wake_by_ref();
        } else {
            let mut st = self.state.lock().unwrap();
            st.waker = Some(cx.waker().clone());
        }

        Poll::Pending
    }
}

pub(crate) struct DriverState<T: Transport> {
    waker: Option<Waker>,
    events_waker: Option<Waker>,
    transport: T,
    commands: VecDeque<ClientCommand>,
    core: Core,
    current_send: Option<Bytes>,
    current_read: BytesMut,
    send_offset: usize,
    core_events: VecDeque<CoreEvent>,
    closed: bool,
}

impl<T: Transport> DriverState<T> {
    fn enqueue_command(&mut self, command: ClientCommand) {
        self.commands.push_back(command);
    }

    fn drive_commands(&mut self) -> io::Result<bool> {
        let mut progress = false;
        while let Some(command) = self.commands.pop_front() {
            progress = true;
            match command {
                ClientCommand::Close => {
                    self.core
                        .close()
                        .map_err(|e| io::Error::other(e.to_string()))?;
                }
            }
        }
        Ok(progress)
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
                        self.closed = true;
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
            self.core
                .handle(current)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            return Ok(true);
        }

        Ok(false)
    }

    fn drive_events(&mut self) -> io::Result<(bool, Option<Waker>)> {
        let mut progress = false;
        while let Some(event) = self.core.poll_event() {
            progress = true;
            self.core_events.push_back(event);
        }
        let mut waker = None;
        if progress {
            waker = self.events_waker.take();
        }
        Ok((progress, waker))
    }
}

pub(crate) enum ClientCommand {
    Close,
}

pub struct Client<T: Transport> {
    driver_state: Arc<Mutex<DriverState<T>>>,
}

impl<T: Transport> Client<T> {
    fn close(&self) {
        let waker = {
            let mut state = self.driver_state.lock().unwrap();
            state.enqueue_command(ClientCommand::Close);
            state.waker.take()
        };

        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn stream(&self) -> ClientStream<T> {
        ClientStream {
            driver_state: self.driver_state.clone(),
        }
    }
}

pub struct ClientStream<T: Transport> {
    driver_state: Arc<Mutex<DriverState<T>>>,
}

impl<T: Transport> Stream for ClientStream<T> {
    type Item = CoreEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut state = self.driver_state.lock().unwrap();

        if let Some(event) = state.core_events.pop_front() {
            Poll::Ready(Some(event))
        } else if state.closed {
            Poll::Ready(None)
        } else {
            state.events_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
