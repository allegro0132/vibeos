#![cfg(feature = "experimental-root-bundle")]

use std::{path::Path, process::Command};
use vibeos_segment_store::experimental_root_bundle::{
    decode, encode_into, Binding, Roots, MAX_BYTES,
};

#[test]
fn experimental_roots_match_independent_python_framing() {
    let model = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../scripts/experimental-metadata-bundle.py");
    let script = r#"
import importlib.util, sys
spec = importlib.util.spec_from_file_location('bundle_model', sys.argv[1])
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
roots = [(r, bytes((i+r)%251 for i in range(n))) for r,n in [(2,896),(3,3776),(4,137)]]
b, root = m.encode(m.Location(bytes([1])*16, 7, 3, 2), roots)
sys.stdout.buffer.write(root.digest+b)
"#;
    let result = Command::new("python3").arg("-c").arg(script).arg(model).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let parts: Vec<Vec<u8>> = [(2, 896), (3, 3776), (4, 137)].into_iter()
        .map(|(role, n)| (0..n).map(|i| ((i + role) % 251) as u8).collect()).collect();
    let roots = Roots { catalog: &parts[0], authority: &parts[1], allocation: &parts[2] };
    let binding = Binding { store: [1; 16], segment: 7, generation: 3, descriptor: 2 };
    let mut bytes = vec![0; roots.encoded_len(MAX_BYTES).unwrap()];
    let hash = encode_into(binding, roots, &mut bytes, MAX_BYTES).unwrap();
    assert_eq!(bytes.len(), 5065);
    assert_eq!(&result.stdout[..32], hash);
    assert_eq!(&result.stdout[32..], bytes);
    assert_eq!(decode(&result.stdout[32..], binding, hash, MAX_BYTES).unwrap(), roots);
}
