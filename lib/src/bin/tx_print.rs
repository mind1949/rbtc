use btclib::{types::Transaction, util::Saveable};

fn main() {
    let path = if let Some(arg) = std::env::args().nth(1) {
        arg
    } else {
        eprintln!("Usage: tx_print <path>");
        std::process::exit(1)
    };
    if let Ok(file) = std::fs::File::open(path) {
        let tx = Transaction::load(file).expect("Failed to read tx from file");
        println!("{:#?}", tx);
    }
}
