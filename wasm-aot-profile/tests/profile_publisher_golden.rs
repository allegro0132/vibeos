use vibeos_wasm_aot_profile::{
    Challenge, EligibleTerminalEvidence, Phase, ProfilePublisher, ProfileRecordSink, RunId,
    Storage, TargetContext, TargetReady, TargetVerified, TerminalObservation, TranscriptBinding,
    FORMAL_READ_CHUNKS, FORMAL_STDOUT_BYTES, FORMAL_STDOUT_SHA256, FORMAL_WRITE_CHUNKS,
    INTERVAL_CAPACITY, MAX_FORMAL_FUEL,
};

const PRIOR_ACCUMULATOR: u64 = 0x0123_4567_89ab_cdef;
const EXPECTED_ACCUMULATOR: u64 = 0x0ce2_4a87_0336_63a1;
const PREFIX: &[u8] = b"VIBE_WASM_AOT_SAMPLE ";
const FIXTURE: &[u8] = include_bytes!("fixtures/publisher-sample-v1.jsonl");
const PAYLOAD_SHA256: [u8; 32] = [
    0xf6, 0xe4, 0xcc, 0xc1, 0xde, 0xc0, 0x79, 0x99, 0x6b, 0xbd, 0x67, 0x15, 0xda, 0x85, 0x89, 0x78,
    0x8c, 0xf4, 0x78, 0xeb, 0x06, 0x1e, 0x59, 0xe8, 0xe6, 0xf9, 0x33, 0x96, 0x9e, 0xe3, 0x03, 0x2c,
];
const RECORD_SHA256: [u8; 32] = [
    0xdc, 0x0a, 0xaf, 0xe2, 0x35, 0x54, 0x86, 0x2c, 0x39, 0x41, 0xa0, 0x64, 0x40, 0xff, 0x40, 0x4a,
    0xeb, 0xf1, 0x9a, 0xaf, 0x2c, 0xe5, 0x35, 0x86, 0x94, 0x62, 0x5b, 0xeb, 0x0b, 0xdf, 0x89, 0x55,
];

struct GoldenSink {
    bytes: Vec<u8>,
    commits: usize,
}

impl ProfileRecordSink for GoldenSink {
    type Error = ();

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn commit_record(&mut self) -> Result<(), Self::Error> {
        self.commits += 1;
        Ok(())
    }
}

fn verified_from_ready<'a>(ready: TargetReady<'a>) -> TargetVerified<'a> {
    let mut active = match ready.start(TargetContext::CANONICAL, 100) {
        Ok(active) => active,
        Err(_) => panic!("golden target start failed"),
    };
    let token = active.token();
    active.set_phase(token, TargetContext::CANONICAL, 101, Phase::Instantiation);
    active.set_phase(token, TargetContext::CANONICAL, 103, Phase::Abi);
    active.set_phase(token, TargetContext::CANONICAL, 106, Phase::Interpretation);
    active.set_phase(token, TargetContext::CANONICAL, 110, Phase::Host);
    active.set_phase(token, TargetContext::CANONICAL, 115, Phase::Wait);
    active.begin_cleanup(token, TargetContext::CANONICAL, 121);
    let finished = match active.finish(token, TargetContext::CANONICAL, 128) {
        Ok(finished) => finished,
        Err(_) => panic!("golden facade sample failed"),
    };
    match finished.verify() {
        Ok(verified) => verified,
        Err(_) => panic!("golden ledger verification failed"),
    }
}

fn binding() -> TranscriptBinding {
    let mut run_id = [0_u8; 32];
    let mut challenge = [0_u8; 32];
    for index in 0..32 {
        run_id[index] = index as u8;
        challenge[index] = index as u8 + 32;
    }
    TranscriptBinding::new(
        RunId::new(run_id).unwrap(),
        Challenge::new(challenge).unwrap(),
    )
}

fn terminal() -> EligibleTerminalEvidence {
    EligibleTerminalEvidence::validate(TerminalObservation {
        read_chunks: FORMAL_READ_CHUNKS,
        write_chunks: FORMAL_WRITE_CHUNKS,
        fuel_consumed: MAX_FORMAL_FUEL,
        poll_quanta: u64::MAX,
        poll_quanta_exact: true,
        succeeded: true,
        logical_live_after: 0,
        timed_out: false,
        timeout_phase: None,
        exit_status: 0,
        stdout_bytes: FORMAL_STDOUT_BYTES,
        stdout_sha256: FORMAL_STDOUT_SHA256,
        stderr_bytes: 0,
    })
    .unwrap()
}

#[test]
fn public_api_emits_the_frozen_canonical_sample() {
    let mut endpoints = vec![u64::MAX; INTERVAL_CAPACITY];
    let mut phases = vec![u8::MAX; INTERVAL_CAPACITY];
    let ready = TargetReady::new(Storage::new(&mut endpoints, &mut phases).unwrap());
    let expected_binding = binding();
    let published = ProfilePublisher::new(
        GoldenSink {
            bytes: Vec::new(),
            commits: 0,
        },
        expected_binding,
        PRIOR_ACCUMULATOR,
    )
    .publish_profile(verified_from_ready(ready), 3, terminal())
    .unwrap_or_else(|_| panic!("golden publication failed"));

    assert_eq!(published.accumulator(), EXPECTED_ACCUMULATOR);
    assert_eq!(published.binding(), expected_binding);
    let (ready, sink, observed_binding, accumulator) = published.into_parts();
    assert_eq!(ready.next_epoch(), Some(2));
    assert_eq!(observed_binding, expected_binding);
    assert_eq!(accumulator, EXPECTED_ACCUMULATOR);
    assert_eq!(sink.commits, 1);
    assert_eq!(sink.bytes.as_slice(), FIXTURE);
    assert_eq!(sink.bytes.len(), 1_392);
    assert!(sink.bytes.starts_with(PREFIX));
    assert_eq!(sink.bytes.last(), Some(&b'\n'));

    let payload = &sink.bytes[PREFIX.len()..sink.bytes.len() - 1];
    assert_eq!(payload.len(), 1_370);
    assert_eq!(sha256(payload), PAYLOAD_SHA256);
    assert_eq!(sha256(&sink.bytes), RECORD_SHA256);
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = [
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64) * 8;
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes(chunk[offset..offset + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let upper = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(upper)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let lower = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = lower.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut digest = [0_u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}
