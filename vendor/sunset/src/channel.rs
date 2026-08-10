use self::packets::ExitSignal;

#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::num::NonZeroUsize;
use core::task::Waker;

use heapless::{String, Vec};

use crate::{runner::set_waker, *};
use config::*;
use conn::DispatchEvent;
use event::{CliEventId, ServEventId};
use packets::{
    ChannelData, ChannelDataExt, ChannelOpen, ChannelOpenType, ChannelReqType,
    ChannelRequest, Packet,
};
use runner::ChanHandle;
use sshnames::*;
use sshwire::{BinString, SSHEncodeEnum, TextString};
use traffic::TrafSend;

pub(crate) struct Channels {
    ch: [Option<Channel>; config::MAX_CHANNELS],
    is_client: bool,
    /// The strict VibeOS server profile accepts at most one session channel for
    /// the lifetime of a connection, even after that channel has closed.
    session_accepted: bool,
}

impl Channels {
    pub fn new(is_client: bool) -> Self {
        Channels { ch: Default::default(), is_client, session_accepted: false }
    }

    pub fn open<'b>(
        &mut self,
        ty: packets::ChannelOpenType<'b>,
    ) -> Result<(ChanNum, Packet<'b>)> {
        let num = self.unused_chan()?;

        let chan = Channel::new(num, (&ty).into());
        let p = packets::ChannelOpen {
            sender_num: num.0,
            initial_window: chan.recv.window,
            max_packet: chan.recv.max_packet,
            ty,
        }
        .into();
        let ch = &mut self.ch[num.0 as usize];
        let ch = ch.insert(chan);
        Ok((ch.num(), p))
    }

    /// Returns a `Channel` for a local number, any state including `InOpen`.
    fn get_any(&self, num: ChanNum) -> Result<&Channel> {
        self.ch
            .get(num.0 as usize)
            // out of range
            .ok_or(error::BadChannel { num }.build())?
            .as_ref()
            // unused channel
            .ok_or(error::BadChannel { num }.build())
    }

    /// Returns a `Channel` for a local number. Excludes `InOpen` or `Opening` state.
    pub(crate) fn get(&self, num: ChanNum) -> Result<&Channel> {
        let ch = self.get_any(num)?;

        match ch.state {
            ChanState::InOpen | ChanState::Opening => {
                error::BadChannel { num }.fail()
            }
            _ => Ok(ch),
        }
    }

    fn get_any_mut(&mut self, num: ChanNum) -> Result<&mut Channel> {
        self.ch
            .get_mut(num.0 as usize)
            // out of range
            .ok_or(error::BadChannel { num }.build())?
            .as_mut()
            // unused channel
            .ok_or(error::BadChannel { num }.build())
    }

    fn get_mut(&mut self, num: ChanNum) -> Result<&mut Channel> {
        let ch = self.get_any_mut(num)?;

        match ch.state {
            ChanState::InOpen | ChanState::Opening => {
                error::BadChannel { num }.fail()
            }
            _ => Ok(ch),
        }
    }

    pub fn by_handle_mut(&mut self, handle: &ChanHandle) -> &mut Channel {
        self.get_mut(handle.0).unwrap()
    }

    /// Must be called when an application has finished with a channel.
    pub fn done(&mut self, num: ChanNum) -> Result<()> {
        let remove_now = {
            let ch = self.get_mut(num)?;
            debug_assert!(!ch.app_done);
            matches!(ch.state, ChanState::PendingDone | ChanState::RecvClose)
        };
        if remove_now {
            self.remove_any(num)?;
        } else {
            let ch = self.get_mut(num)?;
            ch.app_done = true;
            // Once the application has released the channel there is no
            // consumer to benefit from granting the peer more input credit.
            ch.pending_adjust = 0;
        }
        Ok(())
    }

    fn remove_any(&mut self, num: ChanNum) -> Result<()> {
        trace!("remove_any channel {}", num);
        self.ch[num.0 as usize] = None;
        Ok(())
    }

    fn remove(&mut self, num: ChanNum) -> Result<()> {
        // TODO any checks?
        let ch = self.get_any_mut(num)?;
        if ch.app_done {
            trace!("removing channel {}", num);
            self.ch[num.0 as usize] = None;
        } else if !matches!(ch.state, ChanState::RecvClose) {
            ch.state = ChanState::PendingDone;
            ch.pending_adjust = 0;
            trace!("not removing channel {}, not finished", num);
        } else {
            trace!("retaining closed channel {} until application done", num);
        }
        Ok(())
    }

    /// Returns the first available channel
    fn unused_chan(&self) -> Result<ChanNum> {
        self.ch
            .iter()
            .enumerate()
            .find_map(|(i, ch)| {
                if ch.as_ref().is_none() { Some(ChanNum(i as u32)) } else { None }
            })
            .ok_or(Error::NoChannels)
    }

    /// Creates a new channel in InOpen state.
    fn reserve_chan(&mut self, co: &ChannelOpen) -> Result<&mut Channel> {
        let num = self.unused_chan()?;
        let mut chan = Channel::new(num, (&co.ty).into());
        chan.send = Some(ChanDir {
            num: co.sender_num,
            max_packet: co.max_packet,
            window: co.initial_window,
        });
        chan.state = ChanState::InOpen;

        let ch = &mut self.ch[num.0 as usize];
        *ch = Some(chan);
        Ok(ch.as_mut().unwrap())
    }

    /// Prepare a channel data packet without consuming the peer's send window.
    ///
    /// The caller must enqueue the returned packet first, then call
    /// [`Self::commit_send_data`]. This keeps a recoverable transport-output
    /// failure from consuming window credit for bytes that were never queued.
    /// Caller has already checked valid length with send_allowed() and
    /// validated `dt`.
    /// Don't call with zero length data.
    pub(crate) fn prepare_send_data<'b>(
        &self,
        num: ChanNum,
        dt: ChanData,
        data: &'b [u8],
    ) -> Result<Packet<'b>> {
        debug_assert!(!data.is_empty());

        let ch = self.get(num)?;
        let send = ch.send.as_ref().trap()?;
        let Ok(data_len) = u32::try_from(data.len()) else {
            return Error::bug_msg("channel data length exceeds uint32");
        };
        if data_len > send.max_packet || data_len > send.window {
            trace!(
                "data len {}, max {}, window {}",
                data.len(),
                send.max_packet,
                send.window
            );
            return Error::bug();
        }

        let data = BinString(data);
        let p = match dt {
            ChanData::Normal => packets::ChannelData { num: send.num, data }.into(),
            ChanData::Stderr => packets::ChannelDataExt {
                num: send.num,
                code: sshnames::SSH_EXTENDED_DATA_STDERR,
                data,
            }
            .into(),
        };

        Ok(p)
    }

    /// Commit peer-window credit only after the prepared packet was queued.
    pub(crate) fn commit_send_data(
        &mut self,
        num: ChanNum,
        data_len: usize,
    ) -> Result<()> {
        let Ok(data_len) = u32::try_from(data_len) else {
            return Error::bug_msg("channel data length exceeds uint32");
        };
        let ch = self.get_mut(num)?;
        let send = ch.send.as_mut().trap()?;
        if data_len == 0 || data_len > send.max_packet || data_len > send.window {
            return Error::bug_msg("prepared channel data changed before commit");
        }
        send.window -= data_len;
        trace!("send_data: new window {}", send.window);
        if send.window == 0 {
            debug!("ch {num} send window empty");
        }
        Ok(())
    }

    /// Informs the channel layer that an incoming packet has been read out.
    pub(crate) fn finished_read(
        &mut self,
        num: ChanNum,
        len: usize,
        s: &mut TrafSend,
    ) -> Result<()> {
        let ch = self.get_mut(num)?;
        ch.finished_input(len)?;
        ch.check_send_window_adjust(s)?;
        Ok(())
    }

    pub(crate) fn have_recv_eof(&self, num: ChanNum) -> bool {
        self.get(num).is_ok_and(|c| c.have_recv_eof())
    }

    pub(crate) fn is_closed(&self, num: ChanNum) -> bool {
        self.get(num).is_ok_and(|c| c.is_closed())
    }

    pub(crate) fn send_allowed(&self, num: ChanNum) -> Option<usize> {
        self.get(num).map_or(Some(0), |c| c.send_allowed())
    }

    pub(crate) fn valid_send(&self, num: ChanNum, dt: ChanData) -> bool {
        self.get(num).is_ok_and(|c| c.valid_send(dt))
    }

    pub fn progress(&mut self, s: &mut TrafSend) -> Result<DispatchEvent> {
        for ch in self.ch.iter_mut().filter_map(|c| c.as_mut()) {
            ch.check_send_window_adjust(s)?;

            if ch.open_confirmed {
                ch.open_confirmed = false;
                match ch.ty {
                    ChanType::Session => {
                        return Ok(DispatchEvent::CliEvent(
                            CliEventId::SessionOpened(ch.num()),
                        ));
                    }
                    ChanType::Tcp => {
                        trace!("TODO tcp channel")
                    }
                }
            }
        }
        Ok(DispatchEvent::None)
    }

    /// Wake the channel with a ready input data packet.
    pub fn wake_read(&mut self, num: ChanNum, dt: ChanData, is_client: bool) {
        if let Ok(ch) = self.get_mut(num) {
            ch.wake_read(dt, is_client);
        } else {
            debug_assert!(false, "wake_read bad channel");
        }
    }

    /// Wake all ready output channels
    pub fn wake_write(&mut self, is_client: bool) {
        for ch in self.ch.iter_mut().filter_map(|c| c.as_mut()) {
            ch.wake_write(is_client)
        }
    }

    pub(crate) fn term_window_change(
        &self,
        num: ChanNum,
        winch: &packets::WinChange,
        s: &mut TrafSend,
    ) -> Result<()> {
        let ch = self.get(num)?;
        match ch.ty {
            ChanType::Session => Req::WinChange(winch.clone()).send(ch, s),
            _ => error::BadChannelData.fail(),
        }
    }

    pub(crate) fn term_break(
        &self,
        num: ChanNum,
        length: u32,
        s: &mut TrafSend,
    ) -> Result<()> {
        let ch = self.get(num)?;
        let br = packets::Break {
            length: if length == 0 { 0 } else { length.clamp(500, 3000) },
        };
        match ch.ty {
            ChanType::Session => Req::Break(br).send(ch, s),
            _ => error::BadChannelData.fail(),
        }
    }

    fn dispatch_open(
        &mut self,
        p: &ChannelOpen<'_>,
        s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        match self.dispatch_open_inner(p) {
            Err(DispatchOpenError::Failure(f)) => {
                s.send(packets::ChannelOpenFailure {
                    num: p.sender_num,
                    reason: f as u32,
                    desc: "".into(),
                    lang: "",
                })?;
                Ok(DispatchEvent::None)
            }
            Err(DispatchOpenError::Error(e)) => Err(e),
            Ok(ev) => Ok(ev),
        }
    }

    // the caller will send failure messages if required
    fn dispatch_open_inner(
        &mut self,
        p: &ChannelOpen,
    ) -> Result<DispatchEvent, DispatchOpenError> {
        // Check validity before reserving a channel
        match &p.ty {
            ChannelOpenType::Unknown(u) => {
                error!("Rejecting unknown channel type '{u}'");
                return Err(ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE.into());
            }
            ChannelOpenType::Session if self.is_client => {
                trace!("dispatch not server");
                return Err(error::SSHProto.build().into());
            }
            ChannelOpenType::Session if self.session_accepted => {
                debug!("Rejecting a second session channel");
                return Err(ChanFail::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED.into());
            }
            ChannelOpenType::ForwardedTcpip(_) => {
                // TODO implement it
                debug!("Rejecting forwarded tcp");
                return Err(ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE.into());
            }
            ChannelOpenType::DirectTcpip(_) => {
                // TODO implement it
                debug!("Rejecting direct tcp");
                return Err(ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE.into());
            }
            _ => (),
        }

        // Reserve a channel
        let ch = self.reserve_chan(p)?;

        // Beware that a reserved channel must be cleaned up on failure

        match &p.ty {
            ChannelOpenType::Session => {
                Ok(DispatchEvent::ServEvent(ServEventId::OpenSession {
                    num: ch.num(),
                }))
            }
            // ChannelOpenType::ForwardedTcpip(t) => b.open_tcp_forwarded(handle, t),
            // ChannelOpenType::DirectTcpip(t) => b.open_tcp_direct(handle, t),
            _ => {
                // Checked above
                unreachable!()
            }
        }
    }

    pub fn resume_open(
        &mut self,
        c: ChanNum,
        failure: Option<ChanFail>,
        s: &mut TrafSend,
    ) -> Result<()> {
        if let Some(failure) = failure {
            let sender_num = self.get_any(c)?.send_num()?;
            self.remove_any(c)?;
            s.send(packets::ChannelOpenFailure {
                num: sender_num,
                reason: failure as u32,
                desc: "".into(),
                lang: "",
            })?;
            Ok(())
        } else {
            // Success
            if self.session_accepted {
                return error::BadUsage.fail();
            }
            let packet = self.get_any_mut(c)?.open_done()?;
            self.session_accepted = true;
            s.send(packet)
        }
    }

    // Some returned errors will be caught by caller and returned as SSH messages
    fn dispatch_inner(
        &mut self,
        packet: Packet,
        s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        let mut ev = DispatchEvent::default();
        let is_client = self.is_client;

        match packet {
            Packet::ChannelOpen(p) => {
                ev = self.dispatch_open(&p, s)?;
            }

            Packet::ChannelOpenConfirmation(p) => {
                let ch = self.get_any_mut(ChanNum(p.num))?;
                match ch.state {
                    ChanState::Opening => {
                        debug_assert!(ch.send.is_none());

                        if ch.app_done {
                            return Ok(DispatchEvent::None);
                        }

                        ch.send = Some(ChanDir {
                            num: p.sender_num,
                            max_packet: p.max_packet,
                            window: p.initial_window,
                        });

                        // A future progress() will notify the application.
                        ch.open_confirmed = true;
                        ch.state = ChanState::Normal;
                    }
                    _ => {
                        trace!("Bad channel state {:?}", ch.state);
                        return error::SSHProto.fail();
                    }
                }
            }

            Packet::ChannelOpenFailure(p) => {
                let ch = self.get_any(ChanNum(p.num))?;
                if ch.send.is_some() {
                    // TODO: or just warn?
                    trace!("open failure late?");
                    return error::SSHProto.fail();
                } else {
                    self.remove(ChanNum(p.num))?;
                    // TODO event
                }
            }
            Packet::ChannelWindowAdjust(p) => {
                let chan = self.get_mut(ChanNum(p.num))?;
                chan.adjust_send_window(p.adjust)?;
                // Wake any writers that might have been blocked.
                chan.wake_write(is_client);
            }
            Packet::ChannelData(p) => {
                let ch = self.get_mut(ChanNum(p.num))?;
                let data_len = p.data.0.len();
                ch.accept_input(data_len)?;
                if ch.app_done || ch.sent_close {
                    trace!("Ignoring data for closed application channel");
                } else if let Some(len) = NonZeroUsize::new(data_len) {
                    // TODO check we are expecting input
                    let di =
                        DataIn { num: ChanNum(p.num), dt: ChanData::Normal, len };
                    ev = DispatchEvent::Data(di);
                } else {
                    trace!("Zero length channeldata");
                }
            }
            Packet::ChannelDataExt(p) => {
                let ch = self.get_mut(ChanNum(p.num))?;
                let data_len = p.data.0.len();
                ch.accept_input(data_len)?;
                if ch.app_done || ch.sent_close {
                    trace!("Ignoring data for closed application channel");
                } else if !is_client || p.code != sshnames::SSH_EXTENDED_DATA_STDERR
                {
                    // Discard the data, sunset can't handle this
                    debug!("Ignoring unexpected dt data, code {}", p.code);
                    ch.finished_input(data_len)?;
                } else if let Some(len) = NonZeroUsize::new(data_len) {
                    // TODO check we are expecting input and dt is valid.
                    let di =
                        DataIn { num: ChanNum(p.num), dt: ChanData::Stderr, len };
                    ev = DispatchEvent::Data(di);
                } else {
                    trace!("Zero length channeldataext");
                }
            }
            Packet::ChannelEof(p) => {
                let ch = self.get_mut(ChanNum(p.num))?;
                ch.handle_eof(is_client)?;
            }
            Packet::ChannelClose(p) => {
                let is_client = self.is_client;
                let num = ChanNum(p.num);
                self.get_mut(num)?.handle_close(s, is_client)?;
                self.remove(num)?;
            }
            Packet::ChannelRequest(p) => {
                let is_client = self.is_client;
                match self.get_mut(ChanNum(p.num)) {
                    Ok(ch) => {
                        ev = ch.dispatch_request(&p, s, is_client)?;
                    }
                    Err(_) => debug!("Ignoring request to unknown channel: {p:#?}"),
                }
            }
            Packet::ChannelSuccess(_p) => {
                trace!("channel success, TODO");
            }
            Packet::ChannelFailure(_p) => {
                trace!("channel failure, TODO");
            }
            _ => Error::bug_msg("unreachable")?,
        };

        Ok(ev)
    }

    /// Incoming packet handling
    // TODO: protocol errors etc should perhaps be less fatal,
    // ssh implementations are usually imperfect.
    pub fn dispatch(
        &mut self,
        packet: Packet,
        s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        let r = self.dispatch_inner(packet, s);

        match r {
            Err(Error::BadChannel { num, .. }) => {
                warn!("Ignoring bad channel number {:?}", num);
                // warn!("Ignoring bad channel number {:?}", r.unwrap_err().backtrace());
                Ok(DispatchEvent::default())
            }
            // TODO: close channel on error? or on SSHProtoError?
            r => r,
        }
    }

    pub fn resume_chanreq(
        &mut self,
        p: &Packet,
        success: bool,
        s: &mut TrafSend,
    ) -> Result<()> {
        if let Packet::ChannelRequest(r) = p {
            let num = ChanNum(r.num);
            let remote_num = self.get(num)?.send_num()?;
            let result = if r.want_reply {
                if success {
                    s.send(packets::ChannelSuccess { num: remote_num })
                } else {
                    s.send(packets::ChannelFailure { num: remote_num })
                }
            } else {
                Ok(())
            };
            result?;

            if success {
                self.get_mut(num)?.accept_server_request(&r.req);
            }
            Ok(())
        } else {
            Error::bug()
        }
    }

    pub(crate) fn send_exit_status(
        &mut self,
        num: ChanNum,
        status: u32,
        s: &mut TrafSend,
    ) -> Result<()> {
        let ch = self.get_mut(num)?;
        if !ch.start_accepted || ch.sent_exit_status || ch.sent_eof || ch.sent_close
        {
            return error::BadUsage.fail();
        }
        s.send(ChannelRequest {
            num: ch.send_num()?,
            want_reply: false,
            req: ChannelReqType::ExitStatus(packets::ExitStatus { status }),
        })?;
        ch.sent_exit_status = true;
        Ok(())
    }

    pub(crate) fn send_eof(&mut self, num: ChanNum, s: &mut TrafSend) -> Result<()> {
        let ch = self.get_mut(num)?;
        if !ch.sent_exit_status || ch.sent_eof || ch.sent_close {
            return error::BadUsage.fail();
        }
        s.send(packets::ChannelEof { num: ch.send_num()? })?;
        ch.sent_eof = true;
        Ok(())
    }

    pub(crate) fn send_close(
        &mut self,
        num: ChanNum,
        s: &mut TrafSend,
    ) -> Result<()> {
        let ch = self.get_mut(num)?;
        if !ch.sent_eof || ch.sent_close {
            return error::BadUsage.fail();
        }
        s.send(packets::ChannelClose { num: ch.send_num()? })?;
        ch.sent_close = true;
        ch.pending_adjust = 0;
        Ok(())
    }

    pub fn fetch_servcommand<'p>(&self, p: &Packet<'p>) -> Result<TextString<'p>> {
        match p {
            Packet::ChannelRequest(ChannelRequest {
                req: ChannelReqType::Exec(packets::Exec { command }),
                ..
            })
            | Packet::ChannelRequest(ChannelRequest {
                req:
                    ChannelReqType::Subsystem(packets::Subsystem { subsystem: command }),
                ..
            }) => Ok(*command),
            _ => Error::bug(),
        }
    }

    pub fn fetch_pty<'p>(&self, p: &Packet<'p>) -> Result<PtyMetadata<'p>> {
        match p {
            Packet::ChannelRequest(ChannelRequest {
                req: ChannelReqType::Pty(pty),
                ..
            }) => PtyMetadata::try_from(pty),
            _ => Error::bug(),
        }
    }

    pub fn fetch_window_change(&self, p: &Packet<'_>) -> Result<TerminalSize> {
        match p {
            Packet::ChannelRequest(ChannelRequest {
                req: ChannelReqType::WinChange(window),
                ..
            }) => Ok(TerminalSize::from(window)),
            _ => Error::bug(),
        }
    }

    pub fn fetch_signal<'p>(&self, p: &Packet<'p>) -> Result<&'p str> {
        match p {
            Packet::ChannelRequest(ChannelRequest {
                req: ChannelReqType::Signal(signal),
                ..
            }) => Ok(signal.sig),
            _ => Error::bug(),
        }
    }

    pub fn fetch_break(&self, p: &Packet<'_>) -> Result<u32> {
        match p {
            Packet::ChannelRequest(ChannelRequest {
                req: ChannelReqType::Break(request),
                ..
            }) => Ok(request.length),
            _ => Error::bug(),
        }
    }

    pub fn fetch_env_name<'p>(&self, p: &Packet<'p>) -> Result<TextString<'p>> {
        match p {
            Packet::ChannelRequest(ChannelRequest {
                req: ChannelReqType::Environment(packets::Environment { name, .. }),
                ..
            }) => Ok(*name),
            _ => Error::bug(),
        }
    }

    pub fn fetch_env_value<'p>(&self, p: &Packet<'p>) -> Result<TextString<'p>> {
        match p {
            Packet::ChannelRequest(ChannelRequest {
                req:
                    ChannelReqType::Environment(packets::Environment { name: _, value }),
                ..
            }) => Ok(*value),
            _ => Error::bug(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ChanType {
    Session,
    Tcp,
}

impl From<&ChannelOpenType<'_>> for ChanType {
    fn from(c: &ChannelOpenType) -> Self {
        match c {
            ChannelOpenType::Session => ChanType::Session,
            ChannelOpenType::DirectTcpip(_) => ChanType::Tcp,
            ChannelOpenType::ForwardedTcpip(_) => ChanType::Tcp,
            ChannelOpenType::Unknown(_) => unreachable!(),
        }
    }
}

#[derive(Debug)]
pub struct ModePair {
    pub opcode: u8,
    pub arg: u32,
}

#[derive(Debug)]
pub struct Pty {
    pub term: String<MAX_TERM>,
    pub cols: u32,
    pub rows: u32,
    pub width: u32,
    pub height: u32,
    pub modes: Vec<ModePair, { termmodes::NUM_MODES }>,
}

/// Informational dimensions from a PTY or window-change request.
///
/// Zero fields are valid SSH values and are left for the terminal owner to
/// interpret. Consumers must not use these peer-controlled values directly as
/// allocation sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    pub cols: u32,
    pub rows: u32,
    pub pixel_width: u32,
    pub pixel_height: u32,
}

impl From<&packets::WinChange> for TerminalSize {
    fn from(window: &packets::WinChange) -> Self {
        Self {
            cols: window.cols,
            rows: window.rows,
            pixel_width: window.width,
            pixel_height: window.height,
        }
    }
}

/// Validated, borrowed PTY metadata from the current server request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtyMetadata<'a> {
    pub term: &'a str,
    pub size: TerminalSize,
    pub modes: &'a [u8],
}

const MAX_TERMINAL_MODE_BYTES: usize = 1 + 159 * 5;
const MAX_SIGNAL_NAME_BYTES: usize = 64;

fn validate_terminal_modes(mut modes: &[u8]) -> Result<()> {
    if modes.is_empty() || modes.len() > MAX_TERMINAL_MODE_BYTES {
        return error::SSHProto.fail();
    }
    loop {
        let Some((&opcode, tail)) = modes.split_first() else {
            return error::SSHProto.fail();
        };
        if opcode == 0 {
            return if tail.is_empty() { Ok(()) } else { error::SSHProto.fail() };
        }
        if opcode >= 160 {
            // RFC 4254 reserves these opcodes and requires parsing to stop.
            return Ok(());
        }
        let Some(argument) = tail.get(..4) else {
            return error::SSHProto.fail();
        };
        let _ = u32::from_be_bytes(argument.try_into().unwrap());
        modes = &tail[4..];
    }
}

impl<'a> TryFrom<&packets::PtyReq<'a>> for PtyMetadata<'a> {
    type Error = Error;

    fn try_from(pty: &packets::PtyReq<'a>) -> Result<Self> {
        let term = pty.term.to_ascii()?;
        if term.is_empty()
            || term.len() > MAX_TERM
            || !term.as_bytes().iter().all(|byte| byte.is_ascii_graphic())
        {
            return error::SSHProto.fail();
        }
        validate_terminal_modes(pty.modes.0)?;
        Ok(Self {
            term,
            size: TerminalSize {
                cols: pty.cols,
                rows: pty.rows,
                pixel_width: pty.width,
                pixel_height: pty.height,
            },
            modes: pty.modes.0,
        })
    }
}

impl TryFrom<&packets::PtyReq<'_>> for Pty {
    type Error = Error;
    fn try_from(p: &packets::PtyReq) -> Result<Self, Self::Error> {
        debug!("TODO implement pty modes");
        let metadata = PtyMetadata::try_from(p)?;
        let term = metadata.term.try_into().map_err(|_| error::SSHProto.build())?;
        Ok(Pty {
            term,
            cols: metadata.size.cols,
            rows: metadata.size.rows,
            width: metadata.size.pixel_width,
            height: metadata.size.pixel_height,
            modes: Vec::new(),
        })
    }
}
/// Like a `packets::ChannelReqType` but with storage.
/// Lifetime-free variants have the packet part directly.
#[derive(Debug)]
pub enum Req<'a> {
    // TODO let hook impls provide a string type?
    Shell,
    Exec(&'a str),
    Subsystem(&'a str),
    Pty(Pty),
    WinChange(packets::WinChange),
    Break(packets::Break),
    // Signal,
    // ExitStatus,
    // ExitSignal,
}

impl Req<'_> {
    pub(crate) fn send(self, ch: &Channel, s: &mut TrafSend) -> Result<()> {
        let t;
        let req = match self {
            Req::Shell => ChannelReqType::Shell,
            Req::Pty(pty) => {
                debug!("TODO implement pty modes");
                t = pty.term;
                ChannelReqType::Pty(packets::PtyReq {
                    term: TextString(t.as_bytes()),
                    cols: pty.cols,
                    rows: pty.rows,
                    width: pty.width,
                    height: pty.height,
                    modes: BinString(&[0]),
                })
            }
            Req::Exec(cmd) => {
                ChannelReqType::Exec(packets::Exec { command: cmd.into() })
            }
            Req::Subsystem(cmd) => ChannelReqType::Subsystem(packets::Subsystem {
                subsystem: cmd.into(),
            }),
            Req::WinChange(rt) => ChannelReqType::WinChange(rt),
            Req::Break(rt) => ChannelReqType::Break(rt),
        };

        let p = ChannelRequest {
            num: ch.send_num()?,
            // we aren't handling responses for anything
            want_reply: false,
            req,
        };
        let p: Packet = p.into();
        s.send(p)
    }
}

/// Convenience for the types of session channels that can be opened
pub enum SessionCommand<S: AsRef<str>> {
    Shell,
    Exec(S),
    Subsystem(S),
}

impl<'a, S: AsRef<str> + 'a> From<&'a SessionCommand<S>> for Req<'a> {
    fn from(val: &'a SessionCommand<S>) -> Self {
        match val {
            SessionCommand::Shell => Req::Shell,
            SessionCommand::Exec(s) => Req::Exec(s.as_ref()),
            SessionCommand::Subsystem(s) => Req::Subsystem(s.as_ref()),
        }
    }
}

/// Per-direction channel variables
#[derive(Debug)]
struct ChanDir {
    /// `u32` rather than `ChanNum` because it can also be used
    /// for the sender-side number
    num: u32,
    max_packet: u32,
    window: u32,
}

#[derive(Debug)]
enum ChanState {
    /// An incoming channel open request that has not yet been responded to.
    ///
    /// Not to be used for normal channel messages
    InOpen,

    // TODO: perhaps .get() and .get_mut() should ignore Opening state channels?
    Opening,
    Normal,
    RecvEof,
    // TODO: recvclose state probably shouldn't be possible, we remove it straight away?
    RecvClose,
    /// The channel is unused and ready to close after a call to `done()`
    PendingDone,
}

#[derive(Debug)]
pub(crate) struct Channel {
    ty: ChanType,
    state: ChanState,
    pty_seen: bool,
    pty_accepted: bool,
    start_seen: bool,
    start_accepted: bool,
    sent_exit_status: bool,
    sent_eof: bool,
    sent_close: bool,

    recv: ChanDir,
    /// populated in all states except `Opening`
    send: Option<ChanDir>,

    /// Accumulated bytes for the next window adjustment (inbound data direction)
    pending_adjust: u32,

    full_window: u32,

    /// Set when Open Confirmation is received.
    ///
    /// A subsequent `progress()` will emit a `SessionOpened` event
    /// for the application to handle.
    open_confirmed: bool,

    /// Set once application has called `done()`. The channel
    /// will only be removed from the list
    /// (allowing channel number re-use) if `app_done` is set
    app_done: bool,

    // Wakers for notifying readyness. Usually used for async.
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    /// Will be a stderr read waker for a client, or stderr write waker for
    /// a server.
    ext_waker: Option<Waker>,
}

impl Channel {
    fn new(num: ChanNum, ty: ChanType) -> Self {
        Channel {
            ty,
            state: ChanState::Opening,
            pty_seen: false,
            pty_accepted: false,
            start_seen: false,
            start_accepted: false,
            sent_exit_status: false,
            sent_close: false,
            sent_eof: false,
            recv: ChanDir {
                num: num.0,
                // TODO these should depend on SSH rx buffer size minus overhead
                max_packet: config::DEFAULT_MAX_PACKET,
                window: config::DEFAULT_WINDOW,
            },
            send: None,
            pending_adjust: 0,
            full_window: config::DEFAULT_WINDOW,
            open_confirmed: false,
            app_done: false,
            read_waker: None,
            write_waker: None,
            ext_waker: None,
        }
    }

    /// Local channel number
    pub(crate) fn num(&self) -> ChanNum {
        ChanNum(self.recv.num)
    }

    /// Remote channel number, fails if channel is in progress opening
    ///
    /// Returned as a plain `u32` since it is a different namespace than `ChanNum`.
    /// This is the channel number included in most sent packets.
    pub(crate) fn send_num(&self) -> Result<u32> {
        Ok(self.send.as_ref().trap()?.num)
    }

    pub fn set_read_waker(&mut self, dt: ChanData, is_client: bool, waker: &Waker) {
        match dt {
            ChanData::Normal => {
                set_waker(&mut self.read_waker, waker);
            }
            ChanData::Stderr => {
                if is_client {
                    set_waker(&mut self.ext_waker, waker);
                } else {
                    debug_assert!(false, "server ext read waker");
                }
            }
        }
    }

    pub fn set_write_waker(&mut self, dt: ChanData, is_client: bool, waker: &Waker) {
        match dt {
            ChanData::Normal => {
                set_waker(&mut self.write_waker, waker);
            }
            ChanData::Stderr => {
                if !is_client {
                    set_waker(&mut self.ext_waker, waker);
                } else {
                    debug_assert!(false, "client ext write waker");
                }
            }
        }
    }

    pub fn wake_read(&mut self, dt: ChanData, is_client: bool) {
        match dt {
            ChanData::Normal => {
                if let Some(w) = self.read_waker.take() {
                    w.wake()
                }
            }
            ChanData::Stderr => {
                if is_client {
                    if let Some(w) = self.ext_waker.take() {
                        w.wake()
                    }
                }
            }
        }
    }

    pub fn wake_write(&mut self, is_client: bool) {
        if let Some(w) = self.write_waker.take() {
            w.wake()
        }
        if !is_client {
            if let Some(w) = self.ext_waker.take() {
                w.wake()
            }
        }
    }

    /// Returns an open confirmation reply packet to send.
    /// Must be called with state of `InOpen`.
    fn open_done<'p>(&mut self) -> Result<Packet<'p>> {
        debug_assert!(matches!(self.state, ChanState::InOpen));

        self.state = ChanState::Normal;
        let p = packets::ChannelOpenConfirmation {
            num: self.send_num()?,
            sender_num: self.recv.num,
            initial_window: self.recv.window,
            max_packet: self.recv.max_packet,
        }
        .into();
        Ok(p)
    }

    fn dispatch_request(
        &mut self,
        p: &packets::ChannelRequest,
        s: &mut TrafSend,
        is_client: bool,
    ) -> Result<DispatchEvent> {
        if matches!(self.state, ChanState::RecvClose | ChanState::PendingDone) {
            // CHANNEL_CLOSE is terminal. Do not surface a late request to the
            // application or emit a reply after the close exchange.
            return error::SSHProto.fail();
        }
        if self.sent_close {
            // A peer request can cross our CLOSE in flight. Ignore it without
            // emitting an application event or a post-CLOSE failure reply.
            return Ok(DispatchEvent::None);
        }

        let r = match (is_client, self.app_done) {
            // Reject requests if the application has closed
            // the channel. ChannelEOF is arbitrary.
            (_, true) => Err(Error::ChannelEOF),
            (true, _) => self.dispatch_client_request(p, s),
            (false, _) => self.dispatch_server_request(p),
        };

        match r {
            Ok(_) | Err(Error::Bug) => r,
            Err(_) => {
                // A required failure reply is itself protocol state. Never
                // silently lose it under output backpressure.
                if p.want_reply {
                    s.send(packets::ChannelFailure { num: self.send_num()? })?;
                }
                Ok(DispatchEvent::None)
            }
        }
    }

    fn dispatch_server_request(
        &mut self,
        p: &packets::ChannelRequest,
    ) -> Result<DispatchEvent> {
        if !matches!(self.ty, ChanType::Session) {
            return Err(Error::SSHProtoUnsupported);
        }

        let num = self.num();
        match &p.req {
            ChannelReqType::Pty(pty) if !self.pty_seen && !self.start_seen => {
                PtyMetadata::try_from(pty)?;
                self.pty_seen = true;
                Ok(DispatchEvent::ServEvent(ServEventId::SessionPty { num }))
            }
            ChannelReqType::Shell if !self.start_seen => {
                self.start_seen = true;
                Ok(DispatchEvent::ServEvent(ServEventId::SessionShell { num }))
            }
            ChannelReqType::Exec(_) if !self.start_seen => {
                self.start_seen = true;
                Ok(DispatchEvent::ServEvent(ServEventId::SessionExec { num }))
            }
            ChannelReqType::Subsystem(_) if !self.start_seen => {
                // A rejected program-start request still consumes the single
                // start slot so pipelined shell/exec requests cannot race it.
                self.start_seen = true;
                Err(Error::SSHProtoUnsupported)
            }
            ChannelReqType::WinChange(_) if self.pty_accepted && !p.want_reply => {
                Ok(DispatchEvent::ServEvent(ServEventId::SessionWindowChange {
                    num,
                }))
            }
            ChannelReqType::Signal(signal)
                if self.start_accepted
                    && !p.want_reply
                    && signal.sig.len() <= MAX_SIGNAL_NAME_BYTES =>
            {
                Ok(DispatchEvent::ServEvent(ServEventId::SessionSignal { num }))
            }
            ChannelReqType::Break(_) if self.start_accepted && self.pty_accepted => {
                Ok(DispatchEvent::ServEvent(ServEventId::SessionBreak { num }))
            }
            _ => {
                if let ChannelReqType::Unknown(u) = &p.req {
                    warn!("Unknown channel request name ({} bytes)", u.0.len())
                } else {
                    // OK unwrap: tested for Unknown
                    warn!(
                        "Unhandled channel req \"{}\"",
                        p.req.variant_name().unwrap()
                    )
                };
                Err(Error::SSHProtoUnsupported)
            }
        }
    }

    fn accept_server_request(&mut self, request: &ChannelReqType<'_>) {
        match request {
            ChannelReqType::Pty(_) => self.pty_accepted = true,
            ChannelReqType::Shell | ChannelReqType::Exec(_) => {
                self.start_accepted = true;
            }
            _ => {}
        }
    }

    /// Returns Ok(want_reply: bool) on success
    fn dispatch_client_request(
        &mut self,
        p: &packets::ChannelRequest,
        _s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        if !matches!(self.ty, ChanType::Session) {
            return Err(Error::SSHProtoUnsupported);
        }

        match &p.req {
            ChannelReqType::ExitStatus(_) => {
                Ok(DispatchEvent::CliEvent(CliEventId::SessionExit))
            }
            ChannelReqType::ExitSignal(_sig) => {
                Ok(DispatchEvent::CliEvent(CliEventId::SessionExit))
            }
            _ => {
                if let ChannelReqType::Unknown(u) = &p.req {
                    warn!("Unknown channel req type \"{}\"", u)
                } else {
                    // OK unwrap: tested for Unknown
                    warn!(
                        "Unhandled channel req \"{}\"",
                        p.req.variant_name().unwrap()
                    )
                };
                Err(Error::SSHProtoUnsupported)
            }
        }
    }

    fn handle_eof(&mut self, is_client: bool) -> Result<()> {
        match self.state {
            ChanState::RecvClose => {
                // CLOSE is terminal for the receive direction. A late EOF
                // must never make the channel appear open again.
                self.pending_adjust = 0;
                return Ok(());
            }
            ChanState::Normal => {}
            _ => return error::SSHProto.fail(),
        }

        // Wake readers on EOF
        self.wake_read(ChanData::Normal, is_client);
        if is_client {
            self.wake_read(ChanData::Stderr, is_client);
        }

        self.pending_adjust = 0;
        self.state = ChanState::RecvEof;
        Ok(())
    }

    fn handle_close(&mut self, s: &mut TrafSend, is_client: bool) -> Result<()> {
        //TODO: check existing state?
        if !self.sent_close {
            s.send(packets::ChannelClose { num: self.send_num()? })?;
            self.sent_close = true;
        }

        // Wake readers and writers on EOF
        self.wake_read(ChanData::Normal, is_client);
        if is_client {
            self.wake_read(ChanData::Stderr, is_client);
        }
        self.wake_write(is_client);

        self.pending_adjust = 0;
        self.state = ChanState::RecvClose;
        Ok(())
    }

    /// Debit one inbound data packet from the single receive window shared by
    /// normal and extended data. The peer controls `len`, so every check is
    /// performed before mutating the advertised credit.
    fn accept_input(&mut self, len: usize) -> Result<()> {
        let Ok(len) = u32::try_from(len) else {
            return error::SSHProto.fail();
        };
        if !matches!(self.state, ChanState::Normal)
            || len > self.recv.max_packet
            || len > self.recv.window
        {
            return error::SSHProto.fail();
        }
        self.recv.window -= len;
        Ok(())
    }

    /// Apply peer-granted send credit without exceeding SSH's uint32 window.
    fn adjust_send_window(&mut self, adjust: u32) -> Result<()> {
        if matches!(self.state, ChanState::RecvClose | ChanState::PendingDone) {
            return error::SSHProto.fail();
        }
        let send = self.send.as_mut().trap()?;
        let Some(window) = send.window.checked_add(adjust) else {
            return error::SSHProto.fail();
        };
        send.window = window;
        debug!("ch {} new window +{} = {}", self.recv.num, adjust, send.window);
        Ok(())
    }

    /// Mark an accepted packet as consumed by the application. Credit remains
    /// unavailable to the peer until its WINDOW_ADJUST is successfully queued.
    fn finished_input(&mut self, len: usize) -> Result<()> {
        let Ok(len) = u32::try_from(len) else {
            return Error::bug_msg("channel input credit exceeds uint32");
        };
        let Some(debited) = self.full_window.checked_sub(self.recv.window) else {
            return Error::bug_msg("receive window exceeds its configured maximum");
        };
        let Some(unread) = debited.checked_sub(self.pending_adjust) else {
            return Error::bug_msg("pending receive adjustment exceeds debit");
        };
        if len > unread {
            return Error::bug_msg("application credited unread channel data");
        }
        self.pending_adjust += len;
        Ok(())
    }

    fn have_recv_eof(&self) -> bool {
        matches!(self.state, ChanState::RecvEof | ChanState::RecvClose)
    }

    fn is_closed(&self) -> bool {
        matches!(self.state, ChanState::RecvClose)
    }

    // None on close
    fn send_allowed(&self) -> Option<usize> {
        if self.sent_eof || self.sent_close {
            return None;
        }
        let r = self.send.as_ref().map(|s| s.window.min(s.max_packet) as usize);
        trace!("send_allowed {r:?}");
        r
    }

    pub(crate) fn valid_send(&self, _dt: ChanData) -> bool {
        // TODO: later we should only allow non-pty "session" channels
        // to have dt, for stderr only.
        !self.sent_eof && !self.sent_close
    }

    /// Return the adjustment and resulting receive window when a replenishment
    /// is both necessary and valid. No local credit is restored here.
    fn pending_window_adjust(&self) -> Result<Option<(u32, u32)>> {
        if !matches!(self.state, ChanState::Normal)
            || self.app_done
            || self.sent_close
            || self.pending_adjust <= self.full_window / 2
        {
            return Ok(None);
        }

        let Some(window) = self.recv.window.checked_add(self.pending_adjust) else {
            return Error::bug_msg("receive window adjustment overflow");
        };
        if window > self.full_window {
            return Error::bug_msg("receive window adjustment exceeds maximum");
        }
        Ok(Some((self.pending_adjust, window)))
    }

    /// Commit exactly the adjustment that was queued for transmission.
    fn commit_window_adjust(&mut self, adjust: u32, window: u32) -> Result<()> {
        if self.pending_adjust != adjust
            || self.recv.window.checked_add(adjust) != Some(window)
            || window > self.full_window
        {
            return Error::bug_msg(
                "receive window adjustment changed before commit",
            );
        }
        self.recv.window = window;
        self.pending_adjust = 0;
        Ok(())
    }

    fn try_send_window_adjust<F>(
        &mut self,
        output_closed: bool,
        mut send: F,
    ) -> Result<()>
    where
        F: FnMut(packets::ChannelWindowAdjust) -> Result<()>,
    {
        if output_closed {
            return Ok(());
        }
        let Some((adjust, window)) = self.pending_window_adjust()? else {
            return Ok(());
        };
        let num = self.send.as_ref().trap()?.num;
        let p = packets::ChannelWindowAdjust { num, adjust };
        match send(p) {
            Ok(()) => self.commit_window_adjust(adjust, window)?,
            Err(Error::BusySend { .. }) => {
                // Do nothing, the adjustment will be sent later.
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Send a window adjust packet if required. A full output buffer leaves
    /// both pending and available credit untouched for a later retry.
    fn check_send_window_adjust(&mut self, s: &mut TrafSend) -> Result<()> {
        let output_closed = s.is_output_closed();
        self.try_send_window_adjust(output_closed, |packet| s.send(packet))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DataIn {
    pub num: ChanNum,
    pub dt: ChanData,
    // Zero length data does nothing.
    pub len: NonZeroUsize,
}

/// The result of a channel open request.
pub enum ChanOpened {
    Success,
    /// A channel open response will be sent later (for eg TCP open)
    Defer,
    /// A SSH failure code, as well as returning the passed channel handle
    Failure((ChanFail, ChanHandle)),
}

/// A SSH protocol local channel number
///
/// The number will always be in the range `0 <= num < MAX_CHANNELS`
/// and can be used as an index by applications.
/// Most external application API methods take a `ChanHandle` instead.
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, Ord, PartialOrd)]
pub struct ChanNum(pub u32);

impl core::fmt::Display for ChanNum {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// Channel data type, normal or stderr
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ChanData {
    /// `SSH_MSG_CHANNEL_DATA`
    Normal,
    /// `SSH_MSG_CHANNEL_EXTENDED_DATA`. Only `Stderr` is implemented by Sunset,
    /// other types are not widely used.
    Stderr,
    // Future API:
    // Other(u32),
}

impl ChanData {
    pub(crate) fn validate_send(&self, is_client: bool) -> Result<()> {
        if matches!(self, ChanData::Stderr) && is_client {
            error::BadChannelData.fail()
        } else {
            Ok(())
        }
    }

    pub(crate) fn validate_receive(&self, is_client: bool) -> Result<()> {
        if matches!(self, ChanData::Stderr) && !is_client {
            error::BadChannelData.fail()
        } else {
            Ok(())
        }
    }

    pub(crate) fn packet_offset(&self) -> usize {
        match self {
            ChanData::Normal => ChannelData::DATA_OFFSET,
            ChanData::Stderr => ChannelDataExt::DATA_OFFSET,
        }
    }
}

// for dispatch_open_inner()
enum DispatchOpenError {
    /// A program error
    Error(Error),
    /// A SSH failure response
    Failure(ChanFail),
}

impl From<Error> for DispatchOpenError {
    fn from(e: Error) -> Self {
        match e {
            Error::NoChannels => Self::Failure(ChanFail::SSH_OPEN_RESOURCE_SHORTAGE),
            e => Self::Error(e),
        }
    }
}

impl From<ChanFail> for DispatchOpenError {
    fn from(f: ChanFail) -> Self {
        Self::Failure(f)
    }
}

// constructed from runner::cli_session_opener()
/// Sends shell, command, or other requests to a newly opened session channel
pub struct CliSessionOpener<'g, 'a> {
    pub(crate) ch: &'g Channel,
    pub(crate) s: TrafSend<'g, 'a>,
}

impl<'g, 'a> CliSessionOpener<'g, 'a> {
    /// Returns the channel number associated with this session.
    pub fn channel(&self) -> ChanNum {
        self.ch.num()
    }

    /// Requests a Pseudo-TTY for the channel.
    ///
    /// This must be sent prior to requesting a shell or command.
    /// Shells using a PTY will only receive data on the stdin FD, not stderr.
    // TODO: set a flag in the channel so that it drops data on stderr, to
    // avoid waiting forever for a consumer?
    pub fn pty(&mut self, pty: channel::Pty) -> Result<()> {
        self.send(Req::Pty(pty))
    }

    /// Requests a particular command or shell for a channel
    pub fn cmd<S: AsRef<str>>(&mut self, cmd: &SessionCommand<S>) -> Result<()> {
        self.send(cmd.into())
    }

    pub fn shell(&mut self) -> Result<()> {
        self.send(Req::Shell)
    }

    pub fn exec(&mut self, cmd: impl AsRef<str>) -> Result<()> {
        self.send(Req::Exec(cmd.as_ref()))
    }

    pub fn subsystem(&mut self, cmd: impl AsRef<str>) -> Result<()> {
        self.send(Req::Subsystem(cmd.as_ref()))
    }

    fn send(&mut self, req: Req) -> Result<()> {
        req.send(self.ch, &mut self.s)
    }
}

impl core::fmt::Debug for CliSessionOpener<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CliSessionOpener").finish()
    }
}

#[derive(Debug)]
pub enum CliSessionExit<'g> {
    /// Remote process exited with an exit status code
    Status(u32),
    /// Remote process exited by signal
    Signal(ExitSignal<'g>),
}

impl<'g> CliSessionExit<'g> {
    pub fn new(p: &Packet<'g>) -> Result<Self> {
        match p {
            Packet::ChannelRequest(ChannelRequest {
                req: ChannelReqType::ExitStatus(e),
                ..
            }) => Ok(Self::Status(e.status)),
            Packet::ChannelRequest(ChannelRequest {
                req: ChannelReqType::ExitSignal(e),
                ..
            }) => Ok(Self::Signal(e.clone())),
            _ => Error::bug(),
        }
    }
}

#[cfg(test)]
mod strict_server_tests {
    use super::*;
    use crate::encrypt::KeyState;
    use crate::random::tests::TestRandom;
    use crate::traffic::TrafOut;

    fn normal_channel(window: u32, max_packet: u32) -> Channel {
        let mut channel = Channel::new(ChanNum(0), ChanType::Session);
        channel.state = ChanState::Normal;
        channel.recv.window = window;
        channel.recv.max_packet = max_packet;
        channel.full_window = window;
        channel.send = Some(ChanDir { num: 7, max_packet: u32::MAX, window: 1 });
        channel
    }

    fn pty_request<'a>(modes: &'a [u8]) -> ChannelRequest<'a> {
        ChannelRequest {
            num: 0,
            want_reply: true,
            req: ChannelReqType::Pty(packets::PtyReq {
                term: "xterm-256color".into(),
                cols: 80,
                rows: 24,
                width: 640,
                height: 480,
                modes: BinString(modes),
            }),
        }
    }

    #[test]
    fn server_admits_exactly_one_start_request() {
        let mut channel = Channel::new(ChanNum(0), ChanType::Session);
        let exec = ChannelRequest {
            num: 0,
            want_reply: true,
            req: ChannelReqType::Exec(packets::Exec { command: "echo ok".into() }),
        };

        assert!(matches!(
            channel.dispatch_server_request(&exec),
            Ok(DispatchEvent::ServEvent(ServEventId::SessionExec {
                num: ChanNum(0)
            }))
        ));
        assert!(matches!(
            channel.dispatch_server_request(&exec),
            Err(Error::SSHProtoUnsupported)
        ));

        let shell =
            ChannelRequest { num: 0, want_reply: true, req: ChannelReqType::Shell };
        assert!(matches!(
            Channel::new(ChanNum(0), ChanType::Session)
                .dispatch_server_request(&shell),
            Ok(DispatchEvent::ServEvent(ServEventId::SessionShell {
                num: ChanNum(0)
            }))
        ));

        let mut subsystem_channel = Channel::new(ChanNum(0), ChanType::Session);
        let subsystem = ChannelRequest {
            num: 0,
            want_reply: true,
            req: ChannelReqType::Subsystem(packets::Subsystem {
                subsystem: "sftp".into(),
            }),
        };
        assert!(matches!(
            subsystem_channel.dispatch_server_request(&subsystem),
            Err(Error::SSHProtoUnsupported)
        ));
        assert!(matches!(
            subsystem_channel.dispatch_server_request(&shell),
            Err(Error::SSHProtoUnsupported)
        ));
    }

    #[test]
    fn interactive_requests_follow_accepted_pty_and_start_state() {
        let modes = [1, 0, 0, 0, 3, 0];
        let pty = pty_request(&modes);
        let mut channel = Channel::new(ChanNum(0), ChanType::Session);

        assert!(matches!(
            channel.dispatch_server_request(&pty),
            Ok(DispatchEvent::ServEvent(ServEventId::SessionPty {
                num: ChanNum(0)
            }))
        ));
        assert!(channel.pty_seen);
        assert!(!channel.pty_accepted);
        assert!(matches!(
            channel.dispatch_server_request(&pty),
            Err(Error::SSHProtoUnsupported)
        ));

        let window = ChannelRequest {
            num: 0,
            want_reply: false,
            req: ChannelReqType::WinChange(packets::WinChange {
                cols: 132,
                rows: 43,
                width: 0,
                height: u32::MAX,
            }),
        };
        assert!(matches!(
            channel.dispatch_server_request(&window),
            Err(Error::SSHProtoUnsupported)
        ));
        channel.accept_server_request(&pty.req);
        assert!(channel.pty_accepted);
        assert!(matches!(
            channel.dispatch_server_request(&window),
            Ok(DispatchEvent::ServEvent(ServEventId::SessionWindowChange {
                num: ChanNum(0)
            }))
        ));

        let invalid_reply_window = ChannelRequest { want_reply: true, ..window };
        assert!(matches!(
            channel.dispatch_server_request(&invalid_reply_window),
            Err(Error::SSHProtoUnsupported)
        ));

        let shell =
            ChannelRequest { num: 0, want_reply: true, req: ChannelReqType::Shell };
        assert!(matches!(
            channel.dispatch_server_request(&shell),
            Ok(DispatchEvent::ServEvent(ServEventId::SessionShell {
                num: ChanNum(0)
            }))
        ));

        let signal = ChannelRequest {
            num: 0,
            want_reply: false,
            req: ChannelReqType::Signal(packets::Signal { sig: "INT" }),
        };
        let terminal_break = ChannelRequest {
            num: 0,
            want_reply: true,
            req: ChannelReqType::Break(packets::Break { length: u32::MAX }),
        };
        assert!(matches!(
            channel.dispatch_server_request(&signal),
            Err(Error::SSHProtoUnsupported)
        ));
        assert!(matches!(
            channel.dispatch_server_request(&terminal_break),
            Err(Error::SSHProtoUnsupported)
        ));

        channel.accept_server_request(&shell.req);
        assert!(channel.start_accepted);
        assert!(matches!(
            channel.dispatch_server_request(&signal),
            Ok(DispatchEvent::ServEvent(ServEventId::SessionSignal {
                num: ChanNum(0)
            }))
        ));
        assert!(matches!(
            channel.dispatch_server_request(&terminal_break),
            Ok(DispatchEvent::ServEvent(ServEventId::SessionBreak {
                num: ChanNum(0)
            }))
        ));

        let reply_seeking_signal = ChannelRequest { want_reply: true, ..signal };
        assert!(matches!(
            channel.dispatch_server_request(&reply_seeking_signal),
            Err(Error::SSHProtoUnsupported)
        ));
        let long_signal = "I".repeat(MAX_SIGNAL_NAME_BYTES + 1);
        let long_signal = ChannelRequest {
            num: 0,
            want_reply: false,
            req: ChannelReqType::Signal(packets::Signal { sig: &long_signal }),
        };
        assert!(matches!(
            channel.dispatch_server_request(&long_signal),
            Err(Error::SSHProtoUnsupported)
        ));
    }

    #[test]
    fn pty_metadata_is_bounded_and_preserves_exact_fields() {
        let modes = [1, 0, 0, 0, 3, 0];
        let request = pty_request(&modes);
        let ChannelReqType::Pty(pty) = &request.req else { unreachable!() };
        let metadata = PtyMetadata::try_from(pty).unwrap();
        assert_eq!(metadata.term, "xterm-256color");
        assert_eq!(
            metadata.size,
            TerminalSize { cols: 80, rows: 24, pixel_width: 640, pixel_height: 480 }
        );
        assert_eq!(metadata.modes, modes);

        for invalid in [&[][..], &[1, 0, 0][..], &[1, 0, 0, 0, 3][..], &[0, 1][..]] {
            let request = pty_request(invalid);
            let ChannelReqType::Pty(pty) = &request.req else { unreachable!() };
            assert!(PtyMetadata::try_from(pty).is_err());
        }

        let reserved_stop = pty_request(&[160, 0xff, 0xff]);
        let ChannelReqType::Pty(pty) = &reserved_stop.req else { unreachable!() };
        assert!(PtyMetadata::try_from(pty).is_ok());

        let invalid_term = packets::PtyReq {
            term: "bad term".into(),
            cols: 0,
            rows: 0,
            width: 0,
            height: 0,
            modes: BinString(&[0]),
        };
        assert!(PtyMetadata::try_from(&invalid_term).is_err());
    }

    #[test]
    fn interactive_payload_accessors_preserve_wire_values() {
        let channels = Channels::new(false);
        let modes = [53, 0, 0, 0, 1, 0];
        let pty: Packet = pty_request(&modes).into();
        assert_eq!(channels.fetch_pty(&pty).unwrap().modes, modes);

        let window: Packet = ChannelRequest {
            num: 0,
            want_reply: false,
            req: ChannelReqType::WinChange(packets::WinChange {
                cols: 0,
                rows: u32::MAX,
                width: 1,
                height: 2,
            }),
        }
        .into();
        assert_eq!(
            channels.fetch_window_change(&window).unwrap(),
            TerminalSize {
                cols: 0,
                rows: u32::MAX,
                pixel_width: 1,
                pixel_height: 2,
            }
        );

        let signal: Packet = ChannelRequest {
            num: 0,
            want_reply: false,
            req: ChannelReqType::Signal(packets::Signal { sig: "INT" }),
        }
        .into();
        assert_eq!(channels.fetch_signal(&signal).unwrap(), "INT");

        let terminal_break: Packet = ChannelRequest {
            num: 0,
            want_reply: true,
            req: ChannelReqType::Break(packets::Break { length: u32::MAX }),
        }
        .into();
        assert_eq!(channels.fetch_break(&terminal_break).unwrap(), u32::MAX);
    }

    #[test]
    fn accepted_session_is_never_reopened() {
        let mut channels = Channels::new(false);
        channels.session_accepted = true;
        let open = ChannelOpen {
            sender_num: 7,
            initial_window: 1024,
            max_packet: 512,
            ty: ChannelOpenType::Session,
        };

        assert!(matches!(
            channels.dispatch_open_inner(&open),
            Err(DispatchOpenError::Failure(
                ChanFail::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
            ))
        ));
    }

    #[test]
    fn receive_window_is_shared_bounded_and_restored_only_on_commit() {
        let mut channel = normal_channel(10, 6);

        // Normal and extended data both use this single debit path.
        channel.accept_input(6).unwrap();
        assert_eq!(channel.recv.window, 4);
        channel.accept_input(4).unwrap();
        assert_eq!(channel.recv.window, 0);
        assert!(matches!(channel.accept_input(1), Err(Error::SSHProto { .. })));
        assert_eq!(channel.recv.window, 0);

        let mut too_large = normal_channel(10, 6);
        assert!(matches!(too_large.accept_input(7), Err(Error::SSHProto { .. })));
        assert_eq!(too_large.recv.window, 10);
        too_large.accept_input(0).unwrap();
        assert_eq!(too_large.recv.window, 10);

        let mut consumed = normal_channel(10, 10);
        consumed.accept_input(6).unwrap();
        consumed.finished_input(6).unwrap();
        assert_eq!(consumed.recv.window, 4);
        assert_eq!(consumed.pending_adjust, 6);

        let (adjust, restored) = consumed.pending_window_adjust().unwrap().unwrap();
        assert_eq!((adjust, restored), (6, 10));
        // Merely deciding to send an adjustment does not expose credit.
        assert_eq!(consumed.recv.window, 4);
        consumed.commit_window_adjust(adjust, restored).unwrap();
        assert_eq!(consumed.recv.window, 10);
        assert_eq!(consumed.pending_adjust, 0);
        assert_eq!(consumed.pending_window_adjust().unwrap(), None);
    }

    #[test]
    fn normal_and_extended_packets_share_the_dispatch_receive_window() {
        let mut channels = Channels::new(false);
        channels.ch[0] = Some(normal_channel(10, 10));

        let mut output_buf = [0; 64];
        let mut output = TrafOut::new(&mut output_buf);
        output.close();
        let mut keys = KeyState::new_cleartext();
        let mut random = TestRandom::new(0x71);
        let mut sender = output.sender(&mut keys, &mut random);

        let normal = Packet::ChannelData(packets::ChannelData {
            num: 0,
            data: BinString(b"normal"),
        });
        assert!(matches!(
            channels.dispatch_inner(normal, &mut sender).unwrap(),
            DispatchEvent::Data(DataIn {
                num: ChanNum(0),
                dt: ChanData::Normal,
                ..
            })
        ));
        assert_eq!(channels.get(ChanNum(0)).unwrap().recv.window, 4);

        let extended = Packet::ChannelDataExt(packets::ChannelDataExt {
            num: 0,
            code: sshnames::SSH_EXTENDED_DATA_STDERR,
            data: BinString(b"ext!"),
        });
        assert!(channels.dispatch_inner(extended, &mut sender).unwrap().is_none());
        let channel = channels.get(ChanNum(0)).unwrap();
        assert_eq!(channel.recv.window, 0);
        assert_eq!(channel.pending_adjust, 4);

        let overflow = Packet::ChannelData(packets::ChannelData {
            num: 0,
            data: BinString(b"x"),
        });
        assert!(matches!(
            channels.dispatch_inner(overflow, &mut sender),
            Err(Error::SSHProto { .. })
        ));
        assert_eq!(channels.get(ChanNum(0)).unwrap().recv.window, 0);
    }

    #[test]
    fn window_adjust_busy_and_closed_paths_preserve_credit_for_retry() {
        let mut channel = normal_channel(10, 10);
        channel.accept_input(6).unwrap();
        channel.finished_input(6).unwrap();

        let mut attempted = false;
        channel
            .try_send_window_adjust(true, |_| {
                attempted = true;
                Ok(())
            })
            .unwrap();
        assert!(!attempted);
        assert_eq!((channel.recv.window, channel.pending_adjust), (4, 6));

        channel
            .try_send_window_adjust(false, |_| {
                Err(Error::BusySend {
                    packet: packets::MessageNumber::SSH_MSG_CHANNEL_WINDOW_ADJUST,
                    unsupported: true,
                })
            })
            .unwrap();
        assert_eq!((channel.recv.window, channel.pending_adjust), (4, 6));

        let mut sent = None;
        channel
            .try_send_window_adjust(false, |packet| {
                sent = Some((packet.num, packet.adjust));
                Ok(())
            })
            .unwrap();
        assert_eq!(sent, Some((7, 6)));
        assert_eq!((channel.recv.window, channel.pending_adjust), (10, 0));
    }

    #[test]
    fn duplicate_application_credit_is_rejected_without_mutation() {
        let mut channel = normal_channel(10, 10);
        channel.accept_input(6).unwrap();
        channel.finished_input(6).unwrap();

        let rejected =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                channel.finished_input(1)
            }));
        if let Ok(result) = rejected {
            assert!(matches!(result, Err(Error::Bug)));
        }
        assert_eq!((channel.recv.window, channel.pending_adjust), (4, 6));
    }

    #[test]
    fn peer_window_adjust_rejects_uint32_overflow_atomically() {
        let mut channel = normal_channel(10, 10);
        let send = channel.send.as_mut().unwrap();
        send.window = u32::MAX;

        assert!(matches!(
            channel.adjust_send_window(1),
            Err(Error::SSHProto { .. })
        ));
        assert_eq!(channel.send.as_ref().unwrap().window, u32::MAX);

        // An adjustment sent before the peer observed our CLOSE can cross it
        // on the wire and remains valid for the peer's independent direction.
        channel.sent_close = true;
        channel.send.as_mut().unwrap().window = 1;
        channel.adjust_send_window(1).unwrap();
        assert_eq!(channel.send.as_ref().unwrap().window, 2);

        channel.send.as_mut().unwrap().window = u32::MAX - 1;
        channel.adjust_send_window(1).unwrap();
        assert_eq!(channel.send.as_ref().unwrap().window, u32::MAX);
        assert!(matches!(
            channel.adjust_send_window(1),
            Err(Error::SSHProto { .. })
        ));
        assert_eq!(channel.send.as_ref().unwrap().window, u32::MAX);
    }

    #[test]
    fn outbound_data_consumes_window_only_after_queue_commit() {
        let mut channels = Channels::new(false);
        let mut channel = normal_channel(10, 10);
        channel.send.as_mut().unwrap().window = 10;
        channel.send.as_mut().unwrap().max_packet = 10;
        channels.ch[0] = Some(channel);

        let packet = channels
            .prepare_send_data(ChanNum(0), ChanData::Normal, b"four")
            .unwrap();
        assert!(matches!(packet, Packet::ChannelData(_)));
        assert_eq!(
            channels.get(ChanNum(0)).unwrap().send.as_ref().unwrap().window,
            10
        );

        // A failed transport enqueue simply drops the prepared packet. Retrying
        // prepares the same bytes against the same peer credit.
        drop(packet);
        let retry = channels
            .prepare_send_data(ChanNum(0), ChanData::Normal, b"four")
            .unwrap();
        assert!(matches!(retry, Packet::ChannelData(_)));
        drop(retry);
        channels.commit_send_data(ChanNum(0), 4).unwrap();
        assert_eq!(
            channels.get(ChanNum(0)).unwrap().send.as_ref().unwrap().window,
            6
        );
    }

    #[test]
    fn eof_and_close_are_monotonic_and_retire_receive_credit() {
        let mut eof = normal_channel(10, 10);
        eof.accept_input(6).unwrap();
        eof.finished_input(6).unwrap();
        eof.handle_eof(false).unwrap();
        assert!(matches!(eof.state, ChanState::RecvEof));
        assert_eq!(eof.pending_adjust, 0);
        assert_eq!(eof.pending_window_adjust().unwrap(), None);
        assert!(matches!(eof.accept_input(1), Err(Error::SSHProto { .. })));

        let mut closed = normal_channel(10, 10);
        closed.state = ChanState::RecvClose;
        closed.pending_adjust = 6;
        closed.handle_eof(false).unwrap();
        assert!(matches!(closed.state, ChanState::RecvClose));
        assert!(closed.is_closed());
        assert_eq!(closed.pending_adjust, 0);
        assert!(matches!(closed.accept_input(1), Err(Error::SSHProto { .. })));
        assert!(matches!(closed.adjust_send_window(1), Err(Error::SSHProto { .. })));
    }

    #[test]
    fn close_then_request_never_reaches_the_application_or_output() {
        let mut channels = Channels::new(false);
        let mut channel = normal_channel(10, 10);
        channel.state = ChanState::RecvClose;
        channels.ch[0] = Some(channel);

        let mut output_buf = [0; 64];
        let mut output = TrafOut::new(&mut output_buf);
        let mut keys = KeyState::new_cleartext();
        let mut random = TestRandom::new(0x72);
        let mut sender = output.sender(&mut keys, &mut random);
        let shell = Packet::ChannelRequest(ChannelRequest {
            num: 0,
            want_reply: true,
            req: ChannelReqType::Shell,
        });

        assert!(matches!(
            channels.dispatch_inner(shell, &mut sender),
            Err(Error::SSHProto { .. })
        ));
        assert!(!channels.get(ChanNum(0)).unwrap().start_seen);

        let mut crossed = Channels::new(false);
        let mut channel = normal_channel(10, 10);
        channel.sent_close = true;
        crossed.ch[0] = Some(channel);
        let shell = Packet::ChannelRequest(ChannelRequest {
            num: 0,
            want_reply: true,
            req: ChannelReqType::Shell,
        });
        assert!(crossed.dispatch_inner(shell, &mut sender).unwrap().is_none());
        assert!(!crossed.get(ChanNum(0)).unwrap().start_seen);

        let data = Packet::ChannelData(packets::ChannelData {
            num: 0,
            data: BinString(b"x"),
        });
        assert!(crossed.dispatch_inner(data, &mut sender).unwrap().is_none());
        let channel = crossed.get(ChanNum(0)).unwrap();
        assert_eq!(channel.recv.window, 9);
        assert_eq!(channel.pending_adjust, 0);
        assert!(output.output_buf().is_empty());
    }

    #[test]
    fn application_done_retires_pending_receive_credit() {
        let mut channels = Channels::new(false);
        let mut channel = normal_channel(10, 10);
        channel.accept_input(6).unwrap();
        channel.finished_input(6).unwrap();
        channels.ch[0] = Some(channel);

        channels.done(ChanNum(0)).unwrap();
        let channel = channels.get(ChanNum(0)).unwrap();
        assert!(channel.app_done);
        assert_eq!(channel.recv.window, 4);
        assert_eq!(channel.pending_adjust, 0);
        assert_eq!(channel.pending_window_adjust().unwrap(), None);
    }
}
