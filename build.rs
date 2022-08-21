use cfgrammar::yacc::YaccKind;
use lrlex::{CTLexerBuilder, DefaultLexeme};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
