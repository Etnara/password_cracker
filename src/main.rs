use std::env;

fn main() {

    let args: Vec<String> = env::args().collect();

    // Add check for number and type of arguments
    // Probably a help page as well
    let first: &String = &args[1];
    let second: &String = &args[2];

    println!("First argument: {:?}\nSecond argument: {:?}", first, second);
}
