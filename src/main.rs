use rand::Rng;
use std::env;
use std::fs;
use std::process;

fn main() {
    // Collect the command line arguments into a vector of strings
    let input: Vec<String> = env::args().collect();

    // Create a struct to hold the arguments
    let args = Arguments::parse(&input);

    // Call attack function
    match args.attack_type {
        Attack::BruteForce => brute_force(&args.password),
        Attack::Dictionary => dictionary_attack(&args.password, args.dict_arr),
        _ => help(),
    }
}

struct Arguments {
    password: String,
    attack_type: Attack,
    dict_arr: Vec<String>,
}

#[derive(PartialEq)]
enum Attack {
    Undefined,
    BruteForce,
    Dictionary,
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
            "dictionary.txt".to_string()
        };

        // Check if dictionary file exists
        if fs::metadata(&dict_path).is_err() {
            println!("Dictionary file not found");
            process::exit(1);
        }

        // Read dictionary file and split into a vector of &str which is then converted to a vector of Strings
        let dictionary = fs::read_to_string(dict_path).expect("Unable to read file");
        let dict_arr_str: Vec<&str> = dictionary.split("\r\n").collect(); // Windows
        let dict_arr: Vec<String> = dict_arr_str.iter().map(|s| s.to_string()).collect();

        Arguments {
            password,
            attack_type,
            dict_arr,
        }
    }
}

fn help() {
    println!("Usage: <Password> <Style> [Dictionary]");
    process::exit(1);
}

fn brute_force(password: &str) {
    println!("Password: {password}");
}

fn dictionary_attack(password: &str, dict_arr: Vec<String>) {
    println!("Password: {password}\nDictionary: {dict_arr:?}");
}
