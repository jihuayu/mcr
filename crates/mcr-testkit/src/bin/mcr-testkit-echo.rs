use std::process;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = 0;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--stdout" => {
                stdout = args.next().unwrap_or_default();
            }
            "--stderr" => {
                stderr = args.next().unwrap_or_default();
            }
            "--exit" => {
                exit_code = args
                    .next()
                    .and_then(|value| value.parse::<i32>().ok())
                    .unwrap_or(1);
            }
            _ => {}
        }
    }

    print!("{stdout}");
    eprint!("{stderr}");
    process::exit(exit_code);
}
