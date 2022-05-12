

pub fn rust_arr_2_c_char(arr: Vec<u8>) -> String {
    let mut vec: Vec<u8> = Vec::new();

    for u in &arr {
        if *u as char == '\0' {
            break;
        }
        vec.push(*u);
    }

    let str = unsafe { String::from_utf8_unchecked(vec) };
    return str;
}
