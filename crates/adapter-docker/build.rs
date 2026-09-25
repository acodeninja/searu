fn main() {
    println!("cargo:rerun-if-env-changed=SEARU_IMAGE_VERSION");
    println!("cargo:rerun-if-env-changed=SEARU_IMAGE_REGISTRY");
}
