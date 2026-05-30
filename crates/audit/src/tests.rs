#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::canonical::FLAG_HAS_FRAME;

    fn make_frame() -> Vec<u8> {
        vec![0xAB; andna_contracts::FRAME_V2_LEN]
    }

    #[test]
    fn t1_normal_run_passes() {
        let sink = init_sink_if_needed("ffi-0.1.0");
        let mut s = sink.lock().unwrap();
        s.reset_run("ffi-0.1.0");

        let frame = make_frame();

        s.append_verify(VerifyEventInput {
            ts_unix_ms: sink::now_ms(),
            decision: 1,
            engine: 1,
            err_code: 0,
            notes_flags: 0,
            frame_bytes: Some(&frame),
            frame_hash: None,
        });

        let mut tampered = frame.clone();
        tampered[0] ^= 1;
        s.append_verify(VerifyEventInput {
            ts_unix_ms: sink::now_ms(),
            decision: 0,
            engine: 1,
            err_code: 6,
            notes_flags: 0,
            frame_bytes: Some(&tampered),
            frame_hash: None,
        });

        s.append_verify(VerifyEventInput {
            ts_unix_ms: sink::now_ms(),
            decision: 1,
            engine: 1,
            err_code: 0,
            notes_flags: 0,
            frame_bytes: Some(&frame),
            frame_hash: None,
        });

        let snap = s.snapshot();
        validate_records(&snap).unwrap();

        let jsonl = export_jsonl::to_jsonl(&snap);
        validate_jsonl(&jsonl).unwrap();
    }

    #[test]
    fn t2_tamper_detection_fails() {
        let sink = init_sink_if_needed("ffi-0.1.0");
        let mut s = sink.lock().unwrap();
        s.reset_run("ffi-0.1.0");

        let frame = make_frame();
        s.append_verify(VerifyEventInput {
            ts_unix_ms: sink::now_ms(),
            decision: 1,
            engine: 1,
            err_code: 0,
            notes_flags: 0,
            frame_bytes: Some(&frame),
            frame_hash: None,
        });

        let mut snap = s.snapshot();
        // flip one bit in decision
        snap[0].decision ^= 1;
        assert!(validate_records(&snap).is_err());
    }

    #[test]
    fn t3_reorder_detection_fails() {
        let sink = init_sink_if_needed("ffi-0.1.0");
        let mut s = sink.lock().unwrap();
        s.reset_run("ffi-0.1.0");

        let frame = make_frame();
        s.append_verify(VerifyEventInput {
            ts_unix_ms: sink::now_ms(),
            decision: 1,
            engine: 1,
            err_code: 0,
            notes_flags: 0,
            frame_bytes: Some(&frame),
            frame_hash: None,
        });

        let mut frame2 = frame.clone();
        frame2[1] ^= 1;
        s.append_verify(VerifyEventInput {
            ts_unix_ms: sink::now_ms(),
            decision: 0,
            engine: 1,
            err_code: 6,
            notes_flags: 0,
            frame_bytes: Some(&frame2),
            frame_hash: None,
        });

        let mut snap = s.snapshot();
        snap.swap(0, 1);
        assert!(validate_records(&snap).is_err());
    }

    #[test]
    fn missing_frame_rule_enforced() {
        let sink = init_sink_if_needed("ffi-0.1.0");
        let mut s = sink.lock().unwrap();
        s.reset_run("ffi-0.1.0");

        // has_frame=0 => frame_hash must be zeros
        let rec = s.append_verify(VerifyEventInput {
            ts_unix_ms: sink::now_ms(),
            decision: 0,
            engine: 1,
            err_code: 1,
            notes_flags: 0,
            frame_bytes: None,
            frame_hash: None,
        });

        assert_eq!(rec.notes_flags & FLAG_HAS_FRAME, 0);
        assert_eq!(rec.frame_hash, [0u8; 32]);
    }
}