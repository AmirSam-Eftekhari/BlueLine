use std::process::Command;

const API_KEY: &str = "sk_live_abcdEFGH12345678";

fn run_shell(user_input: &str) {
    unsafe {
        libc::system(user_input.as_ptr() as *const i8);
    }
}

fn run_command(cmd: &str) {
    Command::new("sh").arg("-c").arg(cmd).status().unwrap();
}

fn weak_hash(data: &[u8]) -> [u8; 16] {
    md5::compute(data).into()
}

fn build_query(table: &str) -> String {
    format!("SELECT * FROM {} WHERE active=1", table)
}

fn parse_input() -> i32 {
    std::env::args().nth(1).unwrap().parse::<i32>().unwrap()
}

fn raw_cast(x: u32) -> f32 {
    unsafe { std::mem::transmute(x) }
}
