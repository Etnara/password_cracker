use std::env;
use std::fs;
use std::process;

use rand::Rng;

use bcrypt::verify;
use md5;
use sha2::Digest;

use std::time::Instant;

fn main() {
    // Collect the command line arguments into a vector of strings
    let input: Vec<String> = env::args().collect();

    // Create a struct to hold the arguments
    let args = Arguments::parse(&input);

    // Call attack function
    match (args.attack_type, &args.hash) {
        (Attack::BruteForce, Hash::MD5) => brute_force_md5(&args.password),
        (Attack::BruteForce, Hash::SHA256) => brute_force_sha256(&args.password),
        (Attack::BruteForce, Hash::Bcrypt) => brute_force_bcrypt(&args.password),

        (Attack::Dictionary, Hash::MD5) => dictionary_attack_md5(&args.password.to_ascii_uppercase(), args.dict_arr),
        (Attack::Dictionary, Hash::SHA256) => dictionary_attack_sha256(&args.password.to_ascii_uppercase(), args.dict_arr),
        (Attack::Dictionary, Hash::Bcrypt) => dictionary_attack_bcrypt(&args.password, args.dict_arr),

        _ => help(),
    }
}

struct Arguments {
    password: String,
    attack_type: Attack,
    dict_arr: Vec<String>,
    hash: Hash,
}

#[derive(PartialEq)]
enum Attack {
    Undefined,
    BruteForce,
    Dictionary,
}

enum Hash {
    MD5,
    SHA256,
    Bcrypt,
}

impl Arguments {
    fn parse(args: &[String]) -> Arguments {
        // Ensure correct number of arguments
        if !(3..5).contains(&args.len()) {
            help()
        }

        // If "random" is passed, select a random password
        let password = if args[1].eq_ignore_ascii_case("random") {
            // Read password file and split into a vector of strings
            let contents = fs::read_to_string("passwords.txt").expect("Unable to read file");
            let content_arr: Vec<&str> = contents.split("\n").collect(); // Unix

            // Select a random password from the vector
            let plain_pass = content_arr[rand::thread_rng().gen_range(0..content_arr.len())].to_string();

            // Hash the password with a random hash function
            let hashed_pass = match rand::thread_rng().gen_range(0..3) {
                0 => (format!("{:X}", md5::compute(plain_pass.as_bytes()))).to_string(),
                1 => (format!("{:X}", sha2::Sha256::digest(plain_pass.as_bytes()))).to_string(),
                2 => (bcrypt::hash(plain_pass.as_bytes(), 4).unwrap()).to_string(),
                _ => "".to_string(),
            };
            hashed_pass
        } else {
            args[1].to_string()
        };

        // Assign attack type
        let attack_type = match args[2].to_lowercase().as_ref() {
            "b" => Attack::BruteForce,
            "brute" => Attack::BruteForce,
            "bruteforce" => Attack::BruteForce,
            "brute_force" => Attack::BruteForce,
            "d" => Attack::Dictionary,
            "dic" => Attack::Dictionary,
            "dict" => Attack::Dictionary,
            "diction" => Attack::Dictionary,
            "dictionary" => Attack::Dictionary,
            _ => Attack::Undefined,
        };

        // Assign hash type
        let hash = match password.len() {
            32 => Hash::MD5,
            64 => Hash::SHA256,
            _ => {
                if verify("", &password).is_ok() {
                    Hash::Bcrypt
                } else {
                    eprintln!("Hash type not supported");
                    process::exit(0);
                }
            }
        };

        // If Brute Force and dictionary is passed, return help and exit
        if args.len() != 3 && attack_type == Attack::BruteForce {
            help()
        }

        // Assign default dictionary if none is provided
        let dict_path = match hash {
                Hash::MD5 => "md5.txt".to_string(),
                Hash::SHA256 => "sha256.txt".to_string(),
                Hash::Bcrypt => "dictionary.txt".to_string(),
            };

        // Check if dictionary file exists
        if fs::metadata(&dict_path).is_err() {
            eprintln!("Dictionary file not found");
            process::exit(1)
        }

        // Read dictionary file and split into a vector of &str which is then converted to a vector of Strings
        let dictionary = fs::read_to_string(dict_path).expect("Unable to read file");
        let dict_arr_str: Vec<&str> = dictionary.split("\n").collect();
        let dict_arr: Vec<String> = dict_arr_str.iter().map(|s| s.to_string()).collect();

        Arguments {
            password,
            attack_type,
            dict_arr,
            hash,
        }
    }
}

fn help() {
    eprintln!("Usage: <'Password Hash'> <Attack Style>");
    process::exit(0);
}

// Brute force a password up to 8 characters including letters, numbers
fn brute_force_md5(password: &str) {
    let now = Instant::now();
    let mut amount = 0;
    // Each length of password
    for i in 1..9 {
        // Create an empty vector of character
        let mut chars: Vec<char> = vec![];
        // Add base characters to the vector
        for _ in 0..i {
            chars.push('a');
        }
        // Loop until all combinations have been tried
        let mut done = false;
        while !done {
            // Convert the vector of characters to a string
            let mut password_attempt = String::new();
            for c in &chars {
                password_attempt.push(*c);
            }
            // Check if the password has been found
            amount += 1;
            if format!("{:X}", md5::compute(&password_attempt)).eq_ignore_ascii_case(password) {
                let elapsed = now.elapsed().as_secs() as f64 + (now.elapsed().subsec_nanos() as f64 / 1000_000_000.0);
                println!("Time Elapsed: {elapsed} seconds");
                println!("Hash Rate: {} hash/s", amount as f64 / elapsed);
                println!("Password found: {}", password_attempt);
                process::exit(0);
            }
            // Increment the vector of characters
            let mut index = chars.len() - 1;
            loop {
                match chars[index] {
                    'z' => chars[index] = 'A',
                    'Z' => chars[index] = '0',
                    '9' => {
                        chars[index] = 'a';

                        if index == 0 {
                            done = true;
                        } else {
                            index -= 1;
                            continue;
                        }
                    }
                    _ => {
                        chars[index] = (chars[index] as u8 + 1) as char;
                    }
                }
                break;
            }
        }
    }
    let elapsed = now.elapsed().as_secs() as f64 + (now.elapsed().subsec_nanos() as f64 / 1000_000_000.0);
    println!("Time Elapsed: {elapsed} seconds");
    println!("Hash Rate: {} hash/s", amount as f64 / elapsed);
    println!("Password not found");
    process::exit(0);
}

fn brute_force_sha256(password: &str) {
    let now = Instant::now();
    let mut amount = 0;
    // Each length of password
    for i in 1..9 {
        // Create an empty vector of character
        let mut chars: Vec<char> = vec![];
        // Add base characters to the vector
        for _ in 0..i {
            chars.push('a');
        }
        // Loop until all combinations have been tried
        let mut done = false;
        while !done {
            // Convert the vector of characters to a string
            let mut password_attempt = String::new();
            for c in &chars {
                password_attempt.push(*c);
            }
            // Check if the password has been found
            amount += 1;
            if format!("{:X}", sha2::Sha256::digest(&password_attempt)).eq_ignore_ascii_case(password) {
                let elapsed = now.elapsed().as_secs() as f64 + (now.elapsed().subsec_nanos() as f64 / 1000_000_000.0);
                println!("Time Elapsed: {elapsed} seconds");
                println!("Hash Rate: {} hash/s", amount as f64 / elapsed);
                println!("Password found: {}", password_attempt);
                process::exit(0);
            }
            // Increment the vector of characters
            let mut index = chars.len() - 1;
            loop {
                match chars[index] {
                    'z' => chars[index] = 'A',
                    'Z' => chars[index] = '0',
                    '9' => {
                        chars[index] = 'a';

                        if index == 0 {
                            done = true;
                        } else {
                            index -= 1;
                            continue;
                        }
                    }
                    _ => {
                        chars[index] = (chars[index] as u8 + 1) as char;
                    }
                }
                break;
            }
        }
    }
    let elapsed = now.elapsed().as_secs() as f64 + (now.elapsed().subsec_nanos() as f64 / 1000_000_000.0);
    println!("Time Elapsed: {elapsed} seconds");
    println!("Hash Rate: {} hash/s", amount as f64 / elapsed);
    println!("Password not found");
    process::exit(0);
}

fn brute_force_bcrypt(password: &str) {
    let now = Instant::now();
    let mut amount = 0;
    // Each length of password
    for i in 1..9 {
        // Create an empty vector of character
        let mut chars: Vec<char> = vec![];
        // Add base characters to the vector
        for _ in 0..i {
            chars.push('a');
        }
        // Loop until all combinations have been tried
        let mut done = false;
        while !done {
            // Convert the vector of characters to a string
            let mut password_attempt = String::new();
            for c in &chars {
                password_attempt.push(*c);
            }
            // Check if the password has been found
            amount += 1;
            if verify(&password_attempt, password).unwrap() {
                let elapsed = now.elapsed().as_secs() as f64 + (now.elapsed().subsec_nanos() as f64 / 1000_000_000.0);
                println!("Time Elapsed: {elapsed} seconds");
                println!("Hash Rate: {} hash/s", amount as f64 / elapsed);
                println!("Password found: {}", password_attempt);
                process::exit(0);
            }
            // Increment the vector of characters
            let mut index = chars.len() - 1;
            loop {
                match chars[index] {
                    'z' => chars[index] = 'A',
                    'Z' => chars[index] = '0',
                    '9' => {
                        chars[index] = 'a';

                        if index == 0 {
                            done = true;
                        } else {
                            index -= 1;
                            continue;
                        }
                    }
                    _ => {
                        chars[index] = (chars[index] as u8 + 1) as char;
                    }
                }
                break;
            }
        }
    }
    let elapsed = now.elapsed().as_secs() as f64 + (now.elapsed().subsec_nanos() as f64 / 1000_000_000.0);
    println!("Time Elapsed: {elapsed} seconds");
    println!("Hash Rate: {} hash/s", amount as f64 / elapsed);
    println!("Password not found");
    process::exit(0);
}

fn dictionary_attack_md5(password: &str, dict_arr: Vec<String>) {
    let now = Instant::now();
    // Loop through the dictionary
    for i in 0..dict_arr.len() {
        let password_attempt = &dict_arr[i];
        // Check if the password has been found
        if password_attempt.contains(password) {
            let elapsed = now.elapsed().as_secs() as f64 + (now.elapsed().subsec_nanos() as f64 / 1000_000_000.0);
            println!("\nTime Elapsed: {elapsed} seconds");
            println!("Hash Rate: {} hash/s", i as f64 / elapsed);
            println!("Password found: {}", &password_attempt[32..].to_string());
            process::exit(0);
        }
    }
    // If the password was not found
    let elapsed = now.elapsed().as_secs() as f64 + (now.elapsed().subsec_nanos() as f64 / 1000_000_000.0);
    println!("\nTime Elapsed: {elapsed} seconds");
    println!("Hash Rate: {} hash/s", dict_arr.len() as f64 / elapsed);
    println!("Password not found");
    process::exit(0);
}

fn dictionary_attack_sha256(password: &str, dict_arr: Vec<String>) {
    let now = Instant::now();
    // Loop through the dictionary
    for i in 0..dict_arr.len() {
        let password_attempt = &dict_arr[i];
        // Check if the password has been found
        if password_attempt.contains(password) {
            let elapsed = now.elapsed().as_secs() as f64 + (now.elapsed().subsec_nanos() as f64 / 1000_000_000.0);
            println!("\nTime Elapsed: {elapsed} seconds");
            println!("Hash Rate: {} hash/s", i as f64 / elapsed);
            println!("Password found: {}", &password_attempt[64..].to_string());
            process::exit(0);
        }
    }
    // If the password was not found
    let elapsed = now.elapsed().as_secs() as f64 + (now.elapsed().subsec_nanos() as f64 / 1000_000_000.0);
    println!("\nTime Elapsed: {elapsed} seconds");
    println!("Hash Rate: {} hash/s", dict_arr.len() as f64 / elapsed);
    println!("Password not found");
    process::exit(0);
}

fn dictionary_attack_bcrypt(password: &str, dict_arr: Vec<String>) {
    let now = Instant::now();
    // Loop through the dictionary
    for i in 0..dict_arr.len() {
        let password_attempt = &dict_arr[i];
        // Check if the password has been found
        if verify(&password_attempt, password).unwrap() {
            let elapsed = now.elapsed().as_secs() as f64 + (now.elapsed().subsec_nanos() as f64 / 1000_000_000.0);
            println!("\nTime Elapsed: {elapsed} seconds");
            println!("Hash Rate: {} hash/s", i as f64 / elapsed);
            println!("Password found: {}", password_attempt);
            process::exit(0);
        }
    }
    // If the password was not found
    let elapsed = now.elapsed().as_secs() as f64 + (now.elapsed().subsec_nanos() as f64 / 1000_000_000.0);
    println!("\nTime Elapsed: {elapsed} seconds");
    println!("Hash Rate: {} hash/s", dict_arr.len() as f64 / elapsed);
    println!("Password not found");
    process::exit(0);
}
