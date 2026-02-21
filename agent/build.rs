fn main() -> anyhow::Result<()> {
    // 编译 C 代码
    cc::Build::new().file("src/transform.c").compile("my_c_lib");

    Ok(())
}
