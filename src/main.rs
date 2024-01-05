use clap::Parser;
use lms_hss::{get_lmots_parameters, serialize_public_key};
use rand::seq::SliceRandom;
use std::io::Write;

/*
 sample run command: create_lms_tests --n 32 --w 8 --tree-height 5 --tests 1 --filename lms_tests_n32_w8.rs
*/

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    n: u8,

    #[arg(long)]
    w: u8,

    #[arg(long)]
    tree_height: u8,

    #[arg(long)]
    tests: u32,

    #[arg(long)]
    filename: String,
}

struct LmsTest {
    test_passed: bool,
    signature: Vec<u8>,
}

const BOILERPLATE_1: &str = r#"/*++

Licensed under the Apache-2.0 license.

Abstract:

    File contains test cases for LMS signature verification. This file is machine generated.

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{Lms, LmsResult, Sha256};
use caliptra_lms_types::{LmsPublicKey, LmsSignature};
use caliptra_registers::sha256::Sha256Reg;
use caliptra_test_harness::test_suite;

struct LmsTest<'a> {
    test_passed: bool,
    signature: &'a [u8],
}

fn test_lms_random_suite() {
    let mut sha256 = unsafe { Sha256::new(Sha256Reg::new()) };
    "#;

const BOILER_PLATE2: &str = r#"
        assert!(head.is_empty());
        let lms_sig = thing2[0];
        let verify_result = Lms::default().verify_lms_signature_generic(
            &mut sha256,
            &MESSAGE,
            &lms_public_key,
            &lms_sig,
        );
        if t.test_passed {
            // if the test is supposed to pass then we better have no errors and a successful verification
            let result = verify_result.unwrap();
            assert_eq!(result, LmsResult::Success)
        } else {
            // if the test is supposed to fail it could be for a number of reasons that could raise a variety of errors
            // if the verification didn't error, then extract the LMS result and ensure it is a failed verification
            if verify_result.is_ok() {
                let result = verify_result.unwrap();
                assert_eq!(result, LmsResult::SigVerifyFailed)
            }
        }
    }
}

test_suite! {
    test_lms_random_suite,
}
"#;

fn write_test_file(
    filename: &str,
    message: &[u8],
    public_key: &[u8],
    tests: &[LmsTest],
    n: u8,
    p: u16,
    height: u8,
) {
    let mut file = std::fs::File::create(filename).unwrap();
    file.write_all(BOILERPLATE_1.as_bytes()).unwrap();

    let buf = format!(
        "\tconst MESSAGE :[u8; {}] = {:?};\n",
        message.len(),
        message
    );
    file.write_all(buf.as_bytes()).unwrap();

    let buf = format!(
        "\tconst PUBLIC_KEY_BYTES: [u8; {}] = {:?};\n",
        public_key.len(),
        public_key
    );
    file.write_all(buf.as_bytes()).unwrap();

    let buf = "\tlet (head, thing1, _tail): (&[u8], &[LmsPublicKey<";
    file.write_all(buf.as_bytes()).unwrap();
    let buf = format!("{}", n / 4);
    file.write_all(buf.as_bytes()).unwrap();
    let buf = ">], &[u8]) = unsafe { PUBLIC_KEY_BYTES.align_to::<LmsPublicKey<";
    file.write_all(buf.as_bytes()).unwrap();
    let buf = format!("{}", n / 4);
    file.write_all(buf.as_bytes()).unwrap();

    let buf = ">>() };
    \tassert!(head.is_empty());
    \tlet lms_public_key = thing1[0];\n";
    file.write_all(buf.as_bytes()).unwrap();

    let buf = format!("\tconst TESTS: [LmsTest; {}] = [\n", tests.len());
    file.write_all(buf.as_bytes()).unwrap();
    for test in tests {
        let buf = format!(
            "\t\tLmsTest{{ test_passed: {}, signature: &{:?}}},\n",
            test.test_passed, test.signature
        );
        file.write_all(buf.as_bytes()).unwrap();
    }
    file.write_all(b"\t];\n").unwrap();

    let buf = "\tfor t in TESTS {
        let (head, thing2, _tail): (&[u8], &[LmsSignature<";
    file.write_all(buf.as_bytes()).unwrap();
    let buf = format!("{}, {}, {}", n / 4, p, height);
    file.write_all(buf.as_bytes()).unwrap();

    let buf = ">], &[u8]) =
            unsafe { t.signature.align_to::<LmsSignature<";
    file.write_all(buf.as_bytes()).unwrap();
    let buf = format!("{}, {}, {}", n / 4, p, height);
    file.write_all(buf.as_bytes()).unwrap();
    file.write_all(">>() };\n".as_bytes()).unwrap();

    file.write_all(BOILER_PLATE2.as_bytes()).unwrap();
}

fn main() {
    let args = Args::parse();
    let valid_height = matches!(args.tree_height, 5 | 10 | 15 | 20);
    if !valid_height {
        println!(
            "Invalid tree height: {} expected one of 5, 10, 15, 20",
            args.tree_height
        );
        return;
    }

    let valid_n = matches!(args.n, 32 | 24);
    if !valid_n {
        println!("Invalid N: {} expected one of 32 or 24", args.n);
        return;
    }

    let valid_w = matches!(args.w, 1 | 2 | 4 | 8);
    if !valid_w {
        println!("Invalid W: {} expected one of 1, 2, 4, 8", args.w);
        return;
    }

    if args.tests < 1 || args.tests > 16 {
        println!(
            "Invalid number of tests: {} expected a number between 1 and 16",
            args.tests
        );
        return;
    }

    println!(
        "Going to create tests for N: {}, W: {}, tree_height: {}",
        args.n, args.w, args.tree_height
    );

    let mut the_lms_type = lms_hss::LmsAlgorithmType::LmsSha256N32H5;
    let mut the_ots_type = lms_hss::LmotsAlgorithmType::LmotsSha256N32W8;
    if args.n == 32 {
        if args.tree_height == 5 {
            the_lms_type = lms_hss::LmsAlgorithmType::LmsSha256N32H5;
        }
        if args.tree_height == 10 {
            the_lms_type = lms_hss::LmsAlgorithmType::LmsSha256N32H10;
        }
        if args.tree_height == 15 {
            the_lms_type = lms_hss::LmsAlgorithmType::LmsSha256N32H15;
        }
        if args.tree_height == 20 {
            the_lms_type = lms_hss::LmsAlgorithmType::LmsSha256N32H20;
        }
        if args.w == 1 {
            the_ots_type = lms_hss::LmotsAlgorithmType::LmotsSha256N32W1;
        }
        if args.w == 2 {
            the_ots_type = lms_hss::LmotsAlgorithmType::LmotsSha256N32W2;
        }
        if args.w == 4 {
            the_ots_type = lms_hss::LmotsAlgorithmType::LmotsSha256N32W4;
        }
        if args.w == 8 {
            the_ots_type = lms_hss::LmotsAlgorithmType::LmotsSha256N32W8;
        }
    }
    if args.n == 24 {
        if args.tree_height == 5 {
            the_lms_type = lms_hss::LmsAlgorithmType::LmsSha256N24H5;
        }
        if args.tree_height == 10 {
            the_lms_type = lms_hss::LmsAlgorithmType::LmsSha256N24H10;
        }
        if args.tree_height == 15 {
            the_lms_type = lms_hss::LmsAlgorithmType::LmsSha256N24H15;
        }
        if args.tree_height == 20 {
            the_lms_type = lms_hss::LmsAlgorithmType::LmsSha256N24H20;
        }
        if args.w == 1 {
            the_ots_type = lms_hss::LmotsAlgorithmType::LmotsSha256N24W1;
        }
        if args.w == 2 {
            the_ots_type = lms_hss::LmotsAlgorithmType::LmotsSha256N24W2;
        }
        if args.w == 4 {
            the_ots_type = lms_hss::LmotsAlgorithmType::LmotsSha256N24W4;
        }
        if args.w == 8 {
            the_ots_type = lms_hss::LmotsAlgorithmType::LmotsSha256N24W8;
        }
    }

    let max_keys = 1 << args.tree_height;
    if args.tests > max_keys {
        println!(
            "Can't create {} tests with a tree height of {}",
            args.tests, args.tree_height
        );
        return;
    }
    let message = "this is the message I want signed".as_bytes();
    let serial_public_key;
    let candidate_keys: Vec<u32> = (0..max_keys).collect();
    let chosen_qs: Vec<u32> = candidate_keys
        .choose_multiple(&mut rand::thread_rng(), args.tests as usize)
        .cloned()
        .collect();
    println!("going to use the following keys: {:?}", chosen_qs);

    let mut lms_tests = vec![];
    if args.n == 32 {
        let (lms_public_key, lms_tree) =
            lms_hss::create_lms_tree::<32>(&the_lms_type, &the_ots_type).unwrap();
        serial_public_key = serialize_public_key(&lms_public_key);

        for offset_q in chosen_qs {
            let the_q_to_use = lms_tree.q + offset_q;
            let lms_sig = lms_hss::lms_sign_message(
                &the_ots_type,
                &the_lms_type,
                message,
                &lms_tree.private_keys[the_q_to_use as usize].clone(),
                the_q_to_use,
                &lms_tree,
            )
            .unwrap();
            let serial_sig = lms_hss::serialize_signature(&lms_sig);
            let test = LmsTest {
                test_passed: true,
                signature: serial_sig.clone(),
            };
            lms_tests.push(test);
        }
    } else {
        let (lms_public_key, lms_tree) =
            lms_hss::create_lms_tree::<24>(&the_lms_type, &the_ots_type).unwrap();
        serial_public_key = serialize_public_key(&lms_public_key);

        for offset_q in chosen_qs {
            let the_q_to_use = lms_tree.q + offset_q;
            let lms_sig = lms_hss::lms_sign_message(
                &the_ots_type,
                &the_lms_type,
                message,
                &lms_tree.private_keys[the_q_to_use as usize].clone(),
                the_q_to_use,
                &lms_tree,
            )
            .unwrap();
            let valid = lms_hss::verify_lms_signature(message, &lms_public_key, &lms_sig).unwrap();
            assert!(valid);
            let serial_sig = lms_hss::serialize_signature(&lms_sig);
            let test = LmsTest {
                test_passed: true,
                signature: serial_sig.clone(),
            };
            lms_tests.push(test);
        }
    }
    let params = get_lmots_parameters(&the_ots_type).unwrap();
    write_test_file(
        &args.filename,
        message,
        &serial_public_key,
        &lms_tests,
        args.n,
        params.p,
        args.tree_height,
    );
}
