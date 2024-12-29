use btclib::{types::Block, util::Saveable};

fn main() {
    let path = if let Some(arg) = std::env::args().nth(1) {
        arg
    } else {
        eprintln!("Usage: block_print <block_file>");
        std::process::exit(1)
    };
    if let Ok(file) = std::fs::File::open(path) {
        let block = Block::load(file).expect("Failed to read block from file");
        println!("{:#?}", block);
    }
}
