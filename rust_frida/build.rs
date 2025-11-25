fn main() {
    cc::Build::new()
        .file("src/transform.c")   // 指定要编译的 C 源文件
        .compile("my_c_lib"); // 生成静态库 libmy_c_lib.a / my_c_lib.lib

    // 如果有额外的 include 路径、宏等也可以在这里配置：
    // .include("path/to/include")
    // .define("SOME_MACRO", None)
}