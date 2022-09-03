use cfgrammar::yacc::YaccKind;
use lrlex::{CTLexerBuilder, DefaultLexeme};
use rerun_except::rerun_except;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    rerun_except(&["LICENSE-APACHE", "LICENSE-MIT", "README.md"])?;

    CTLexerBuilder::<DefaultLexeme<u8>, u8>::new_with_lexemet()
        .lrpar_config(|ctp| {
            ctp.yacckind(YaccKind::Grmtools)
                .grammar_in_src_dir("config.y")
                .unwrap()
        })
        .lexer_in_src_dir("config.l")?
        .build()?;
    Ok(())
}
