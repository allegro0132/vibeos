//! Bounded middlebox sequence tracking, not an endpoint TCP implementation.
//! Tracks the envelope actually granted by observed windows and data/ACK ends.
//! Historical grants are retained for in-flight segments across window shrink;
//! a bounded old-data allowance permits retransmissions/reordering. Endpoint
//! reassembly, PAWS, challenge ACKs and SACK scoreboard semantics remain there.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Segment {
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub payload: usize,
    pub window: u16,
    pub scale: Option<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Side {
    end: u32,
    seq_floor: u32,
    ack_floor: u32,
    acked: u32,
    limit: u32,
    max_credit: u32,
    credit: u32,
    fin: Option<u32>,
    window_seq: u32,
    window_ack: u32,
    scale: Option<u8>,
    syn_window: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tracker {
    sides: [Option<Side>; 2],
}
fn after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}
fn between(value: u32, low: u32, high: u32) -> bool {
    let width = high.wrapping_sub(low);
    width < 0x8000_0000 && value.wrapping_sub(low) <= width
}
impl Side {
    fn syn(s: Segment) -> Self {
        let end = s.seq.wrapping_add(1);
        Self {
            end,
            seq_floor: s.seq,
            ack_floor: end,
            acked: end,
            limit: end,
            max_credit: 1,
            credit: 0,
            fin: None,
            window_seq: s.seq,
            window_ack: s.ack,
            scale: s.scale,
            syn_window: s.window,
        }
    }
    fn grant(&mut self, ack: u32, credit: u32) {
        let limit = ack.wrapping_add(credit);
        if after(limit, self.limit) {
            self.limit = limit;
        }
        self.credit = credit;
        self.max_credit = self.max_credit.max(credit.max(1));
    }
}
impl Tracker {
    /// Caller has already validated the handshake/flag phase. The new value is
    /// returned by copy and must be committed only after packet TX reservation.
    pub fn advance(old: Option<Self>, lan: bool, s: Segment) -> Result<Self, ()> {
        if s.scale.is_some_and(|scale| scale > 14) {
            return Err(());
        }
        let i = if lan { 0 } else { 1 };
        let Some(mut tracker) = old else {
            if !lan || s.flags & 0x17 != 2 || s.payload != 0 {
                return Err(());
            }
            return Ok(Self {
                sides: [Some(Side::syn(s)), None],
            });
        };
        if s.payload > 65535 {
            return Err(());
        }
        if s.flags & 2 != 0 {
            match tracker.sides[i] {
                None => {
                    if lan || s.flags & 0x17 != 0x12 || s.payload != 0 {
                        return Err(());
                    }
                    let mut client = tracker.sides[0].ok_or(())?;
                    if s.ack != client.end {
                        return Err(());
                    }
                    let mut server = Side::syn(s);
                    // SYN/SYN-ACK windows are never scaled, even if both sides
                    // offered WS. Scaling begins with subsequent non-SYNs.
                    client.grant(s.ack, s.window as u32);
                    server.grant(server.end, client.syn_window as u32);
                    tracker.sides = [Some(client), Some(server)];
                }
                Some(side) => {
                    if s.seq.wrapping_add(1) != side.end || s.scale != side.scale || s.payload != 0
                    {
                        return Err(());
                    }
                    // Only handshake/retransmission phases may reach here; an
                    // old SYN after data cannot reset any sequence/window state.
                }
            }
            return Ok(tracker);
        }
        // A SYN rejection RST has no responder sequence history. Its ACK was
        // checked against the initiating SYN by the handshake state machine.
        if tracker.sides[1].is_none() && !lan && s.flags & 0x17 == 0x14 && s.payload == 0 {
            if s.ack == tracker.sides[0].unwrap().end {
                return Ok(tracker);
            }
            return Err(());
        }
        let mut sender = tracker.sides[i].ok_or(())?;
        let mut receiver = tracker.sides[i ^ 1].ok_or(())?;
        let fin = u32::from(s.flags & 1 != 0);
        let end = s.seq.wrapping_add(s.payload as u32).wrapping_add(fin);
        let lower = sender.seq_floor;
        let probe = sender.credit == 0
            && fin == 0
            && s.payload <= 1
            && (s.seq == sender.acked || s.seq == sender.acked.wrapping_sub(1));
        if !probe && (!between(s.seq, lower, sender.limit) || !between(end, lower, sender.limit)) {
            return Err(());
        }
        if s.flags & 0x10 != 0 {
            let low = receiver.ack_floor;
            if !between(s.ack, low, receiver.end) {
                return Err(());
            }
        }
        if s.flags & 4 != 0 {
            // A middlebox does not know the endpoint's exact RCV.NXT through
            // gaps. Accept only observed acknowledged/highest-sent boundaries,
            // never an arbitrary guessed point somewhere inside a large window.
            if s.payload != 0 || fin != 0 || (s.seq != sender.acked && s.seq != sender.end) {
                return Err(());
            }
            return Ok(tracker);
        }
        if let Some(fin_end) = sender.fin {
            if after(end, fin_end) || fin != 0 && end != fin_end {
                return Err(());
            }
        } else if fin != 0 {
            if after(sender.end, end) {
                return Err(());
            }
            sender.fin = Some(end);
        }
        if after(end, sender.end) {
            sender.end = end;
        }
        if s.flags & 0x10 != 0 {
            if after(s.ack, receiver.acked) {
                receiver.acked = s.ack;
            }
            let fresh_window = after(s.seq, sender.window_seq)
                || s.seq == sender.window_seq && !after(sender.window_ack, s.ack);
            if fresh_window {
                let scale = if sender.scale.is_some() && receiver.scale.is_some() {
                    sender.scale.unwrap()
                } else {
                    0
                };
                let credit = (s.window as u32) << scale;
                receiver.grant(s.ack, credit);
                sender.window_seq = s.seq;
                sender.window_ack = s.ack;
            }
        }
        // Floors begin at the handshake, then slide forward without reviving
        // older data/ACKs when a later window grant grows.
        let seq_floor = receiver.acked.wrapping_sub(receiver.max_credit.max(1));
        if after(seq_floor, receiver.seq_floor) {
            receiver.seq_floor = seq_floor;
        }
        let ack_floor = receiver.acked.wrapping_sub(receiver.max_credit.max(65535));
        if after(ack_floor, receiver.ack_floor) {
            receiver.ack_floor = ack_floor;
        }
        tracker.sides[i] = Some(sender);
        tracker.sides[i ^ 1] = Some(receiver);
        Ok(tracker)
    }
}

#[cfg(test)]
mod tests;
