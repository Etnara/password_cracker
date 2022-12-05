use std::env;
use std::process;
use std::fs;
// use std::io::Write;

use rand::Rng;

use md5;
use sha2::Digest;
use bcrypt::verify;

// #[allow(unused_imports)]
// use std::time::Instant;

fn main() {
    // Collect the command line arguments into a vector of strings
    let input: Vec<String> = env::args().collect();

    // Create a struct to hold the arguments
    let args = Arguments::parse(&input);

    // Call attack function
    match args.attack_type {
        Attack::BruteForce => brute_force(&args.password, &args.hash),
        Attack::Dictionary => dictionary_attack(&args.password, args.dict_arr, &args.hash),
        _ => help(),
    }

    // match (args.attack_type, &args.hash) {
    //     (Attack::BruteForce, Hash::MD5) => brute_force(&args.password, &args.hash),
    //     (Attack::BruteForce, Hash::SHA256) => brute_force(&args.password, &args.hash),
    //     (Attack::BruteForce, Hash::Bcrypt) => brute_force(&args.password, &args.hash),
    //
    //     (Attack::Dictionary, Hash::MD5)  => dictionary_attack_md5(&args.password, args.dict_arr),
    //     (Attack::Dictionary, Hash::SHA256)  => dictionary_attack_sha256(&args.password, args.dict_arr),
    //     (Attack::Dictionary, Hash::Bcrypt)  => dictionary_attack_bcrypt(&args.password, args.dict_arr),
    //
    //     _ => help(),
    // }
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

#[derive(PartialEq)]
#[derive(Debug)]
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
            content_arr[rand::thread_rng().gen_range(0..content_arr.len())].to_string()
        } else {
            args[1].to_string()
        };

        // Assign attack type
        let attack_type = match args[2].to_lowercase().as_ref() {
            "brute" => Attack::BruteForce,
            "bruteforce" => Attack::BruteForce,
            "dict" => Attack::Dictionary,
            "dictionary" => Attack::Dictionary,
            _ => Attack::Undefined,
        };

        // If Brute Force and dictionary is passed, return help and exit
        if args.len() != 3 && attack_type == Attack::BruteForce {
            help()
        }

        // Assign default dictionary if none is provided
        let dict_path = if args.len() == 4 {
            args[3].clone()
        } else {
            "dict.txt".to_string()
        };

        // Check if dictionary file exists
        if fs::metadata(&dict_path).is_err() {
            println!("Dictionary file not found");
            process::exit(1)
        }

        // Read dictionary file and split into a vector of &str which is then converted to a vector of Strings
        let dictionary = fs::read_to_string(dict_path).expect("Unable to read file");
        let dict_arr_str: Vec<&str> = dictionary.split("\n").collect(); // Possibly split depending on whether there is a \r or not
        let dict_arr: Vec<String> = dict_arr_str.iter().map(|s| s.to_string()).collect();
        //print!("{:?}", dict_arr);

        // Assign hash type
        let hash = match password.len() {
            32 => Hash::MD5,
            64 => Hash::SHA256,
            _ => {
                if password.starts_with("$2") {
                    Hash::Bcrypt
                } else {
                    println!("Hash type not supported");
                    process::exit(0);
                }
            }
        };

        Arguments {
            password,
            attack_type,
            dict_arr,
            hash,
        }
    }
}

fn help() {
    println!("Usage: <'Password/Hash'> <Style> [Dictionary] -flags");
    process::exit(0);
}

// TODO: Figure out inconsistent speed
// Brute force a password up to 8 characters including letters, numbers
fn brute_force(password: &str, hash: &Hash) {
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

            // Must use '' for bcrypt
            // Check if the password has been found
            // TODO: Fix Bcrypt not showing password that is checked
            if hash.eq(&Hash::Bcrypt) {
                print!("Trying: {password_attempt} \n"); // \r is carriage return to overwrite previous line
            } else {
                print!("Trying: {password_attempt} \r"); // \r is carriage return to overwrite previous line
            }

            if match &hash {
                Hash::MD5 => format!("{:X}", md5::compute(&password_attempt)).eq_ignore_ascii_case(password),
                Hash::SHA256 => format!("{:X}", sha2::Sha256::digest(&password_attempt)).eq_ignore_ascii_case(password),
                Hash::Bcrypt => verify(&password_attempt, password).unwrap(), // TODO: Add error handling to Bcrypt
            }{
                println!("Password found: {}", password_attempt);
                process::exit(0);
            }

            // Bcrypt and Timer
            // let now = Instant::now();
            // {
            //     let _hashed = match bcrypt::verify(&password_attempt, password) {
            //         Ok(r) => println!("Password: {password_attempt} \nHash: {r}"),
            //         Err(_e) => panic!()
            //     };
            // }
            // let elapsed = now.elapsed();
            // let sec = (elapsed.as_secs() as f64) + (elapsed.subsec_nanos() as f64 / 1000_000_000.0);
            //
            // println!("crypt: {}", sec);

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
                    },
                    _ => {
                        chars[index] = (chars[index] as u8 + 1) as char;
                    }
                }
                break;
            }
        }
    }
}

// TODO: Make Rainbow Table
// fn dictionary_attack_md5(password: &str, dict_arr: Vec<String>) {
//     for password_attempt in dict_arr {
//         print!("Trying: {password_attempt} \n"); // \r is carriage return to overwrite previous line
//         if format!("{:X}", md5::compute(&password_attempt)).eq_ignore_ascii_case(password) {
//             println!("Password found: {}", password_attempt);
//             process::exit(0);
//         }
//     }
//         println!("Password not found");
//         process::exit(0);
// }
//
//
// fn dictionary_attack_sha256(password: &str, dict_arr: Vec<String>) {
//     for password_attempt in dict_arr {
//         //print!("Trying: {password_attempt} \n"); // \r is carriage return to overwrite previous line
//         if format!("{:X}", sha2::Sha256::digest(&password_attempt)).eq_ignore_ascii_case(password) {
//             println!("Password found: {}", password_attempt);
//             process::exit(0);
//         }
//     }
//     println!("Password not found");
//     process::exit(0);
// }
//
//
// fn dictionary_attack_bcrypt(password: &str, dict_arr: Vec<String>) {
//     for password_attempt in dict_arr {
//         print!("Trying: {password_attempt} \n"); // \r is carriage return to overwrite previous line
//
//         if verify(&password_attempt, password).unwrap() { // TODO: Add error handling to Bcrypt
//             println!("Password found: {}", password_attempt);
//             process::exit(0);
//         }
//     }
//     println!("Password not found");
//     process::exit(0);
// }


fn dictionary_attack(password: &str, dict_arr: Vec<String>, hash: &Hash) {
    for password_attempt in dict_arr {
        // print!("Trying: {password_attempt} \r\r\r\r\r\r\r\r\r\r\r\r\r"); // \r is carriage return to overwrite previous line
        // print!("Trying: {:?} ", password_attempt); // \r is carriage return to overwrite previous line
        // std::io::stdout().flush().unwrap();
        // print!("\r");
        if match &hash {
            Hash::MD5 => format!("{:X}", md5::compute(&password_attempt)).eq_ignore_ascii_case(password),
            Hash::SHA256 => format!("{:X}", sha2::Sha256::digest(&password_attempt)).eq_ignore_ascii_case(password),
            Hash::Bcrypt => verify(&password_attempt, password).unwrap(), // TODO: Add error handling to Bcrypt
        }{
            println!("Password found: {}", password_attempt);
            process::exit(0);
        }
    }

    println!("Password not found");
    process::exit(0);
}

/* Verbose output
    let _start=
    if dict_arr.contains(&password.to_string()){
        // index for the password - 100
        if dict_arr.iter().position(|x| x == password).unwrap() < 25000 {
            0
        } else {
            dict_arr.iter().position(|x| x == password).unwrap() - 25000
        }
    } else { 0 };

    for i in 0..dict_arr.len() {
        print!("Trying: {}", dict_arr[i]);
        if dict_arr[i] == password {
            println!("\n\nPassword found: {}", dict_arr[i]);
            process::exit(0);
        }
        /*let w = std::io::BufWriter::new(::std::io::stdout().lock())
        writeln!("{}", w).unwrap();*/
    }

    println!("\n\nPassword not found");
    process::exit(0);
                      */
